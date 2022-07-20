#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/blk-integrity.h>
#include <linux/scatterlist.h>
#include <linux/part_stat.h>
#include <linux/blk-cgroup.h>

#include <trace/events/block.h>

#include "blk.h"
#include "blk-mq-sched.h"
#include "blk-rq-qos.h"
#include "blk-throttle.h"

static inline void bio_get_first_bvec(struct bio *bio, struct bio_vec *bv)
{
	*bv = mp_bvec_iter_bvec(bio->bi_io_vec, bio->bi_iter);
}

static inline void bio_get_last_bvec(struct bio *bio, struct bio_vec *bv)
{
	struct bvec_iter iter = bio->bi_iter;
	int idx;

	bio_get_first_bvec(bio, bv);
	if (bv->bv_len == bio->bi_iter.bi_size)
		return;		/* this bio only has a single bvec */

	bio_advance_iter(bio, &iter, iter.bi_size);

	if (!iter.bi_bvec_done)
		idx = iter.bi_idx - 1;
	else	/* in the middle of bvec */
		idx = iter.bi_idx;

	*bv = bio->bi_io_vec[idx];

	if (iter.bi_bvec_done)
		bv->bv_len = iter.bi_bvec_done;
}

static inline bool bio_will_gap(struct request_queue *q,
		struct request *prev_rq, struct bio *prev, struct bio *next)
{
	struct bio_vec pb, nb;

	if (!bio_has_data(prev) || !queue_virt_boundary(q))
		return false;

	if (prev_rq)
		bio_get_first_bvec(prev_rq->bio, &pb);
	else
		bio_get_first_bvec(prev, &pb);
	if (pb.bv_offset & queue_virt_boundary(q))
		return true;

	bio_get_last_bvec(prev, &pb);
	bio_get_first_bvec(next, &nb);
	if (biovec_phys_mergeable(q, &pb, &nb))
		return false;
	return __bvec_gap_to_prev(q, &pb, nb.bv_offset);
}

static inline bool req_gap_back_merge(struct request *req, struct bio *bio)
{
	return bio_will_gap(req->q, req, req->biotail, bio);
}

static inline bool req_gap_front_merge(struct request *req, struct bio *bio)
{
	return bio_will_gap(req->q, NULL, bio, req->bio);
}

static struct bio *blk_bio_discard_split(struct request_queue *q,
					 struct bio *bio,
					 struct bio_set *bs,
					 unsigned *nsegs)
{
	unsigned int max_discard_sectors, granularity;
	int alignment;
	sector_t tmp;
	unsigned split_sectors;

	*nsegs = 1;

	granularity = max(q->limits.discard_granularity >> 9, 1U);

	max_discard_sectors = min(q->limits.max_discard_sectors,
			bio_allowed_max_sectors(q));
	max_discard_sectors -= max_discard_sectors % granularity;

	if (unlikely(!max_discard_sectors)) {
		return NULL;
	}

	if (bio_sectors(bio) <= max_discard_sectors)
		return NULL;

	split_sectors = max_discard_sectors;

	alignment = (q->limits.discard_alignment >> 9) % granularity;

	tmp = bio->bi_iter.bi_sector + split_sectors - alignment;
	tmp = sector_div(tmp, granularity);

	if (split_sectors > tmp)
		split_sectors -= tmp;

	return bio_split(bio, split_sectors, GFP_NOIO, bs);
}

static struct bio *blk_bio_write_zeroes_split(struct request_queue *q,
		struct bio *bio, struct bio_set *bs, unsigned *nsegs)
{
	*nsegs = 0;

	if (!q->limits.max_write_zeroes_sectors)
		return NULL;

	if (bio_sectors(bio) <= q->limits.max_write_zeroes_sectors)
		return NULL;

	return bio_split(bio, q->limits.max_write_zeroes_sectors, GFP_NOIO, bs);
}

static inline unsigned get_max_io_size(struct request_queue *q,
				       struct bio *bio)
{
	unsigned sectors = blk_max_size_offset(q, bio->bi_iter.bi_sector, 0);
	unsigned max_sectors = sectors;
	unsigned pbs = queue_physical_block_size(q) >> SECTOR_SHIFT;
	unsigned lbs = queue_logical_block_size(q) >> SECTOR_SHIFT;
	unsigned start_offset = bio->bi_iter.bi_sector & (pbs - 1);

	max_sectors += start_offset;
	max_sectors &= ~(pbs - 1);
	if (max_sectors > start_offset)
		return max_sectors - start_offset;

	return sectors & ~(lbs - 1);
}

static inline unsigned get_max_segment_size(const struct request_queue *q,
					    struct page *start_page,
					    unsigned long offset)
{
	unsigned long mask = queue_segment_boundary(q);

	offset = mask & (page_to_phys(start_page) + offset);

	return min_not_zero(mask - offset + 1,
			(unsigned long)queue_max_segment_size(q));
}

static bool bvec_split_segs(const struct request_queue *q,
			    const struct bio_vec *bv, unsigned *nsegs,
			    unsigned *sectors, unsigned max_segs,
			    unsigned max_sectors)
{
	unsigned max_len = (min(max_sectors, UINT_MAX >> 9) - *sectors) << 9;
	unsigned len = min(bv->bv_len, max_len);
	unsigned total_len = 0;
	unsigned seg_size = 0;

	while (len && *nsegs < max_segs) {
		seg_size = get_max_segment_size(q, bv->bv_page,
						bv->bv_offset + total_len);
		seg_size = min(seg_size, len);

		(*nsegs)++;
		total_len += seg_size;
		len -= seg_size;

		if ((bv->bv_offset + total_len) & queue_virt_boundary(q))
			break;
	}

	*sectors += total_len >> 9;

	return len > 0 || bv->bv_len > max_len;
}

static struct bio *blk_bio_segment_split(struct request_queue *q,
					 struct bio *bio,
					 struct bio_set *bs,
					 unsigned *segs)
{
	struct bio_vec bv, bvprv, *bvprvp = NULL;
	struct bvec_iter iter;
	unsigned nsegs = 0, sectors = 0;
	const unsigned max_sectors = get_max_io_size(q, bio);
	const unsigned max_segs = queue_max_segments(q);

	bio_for_each_bvec(bv, bio, iter) {
		if (bvprvp && bvec_gap_to_prev(q, bvprvp, bv.bv_offset))
			goto split;

		if (nsegs < max_segs &&
		    sectors + (bv.bv_len >> 9) <= max_sectors &&
		    bv.bv_offset + bv.bv_len <= PAGE_SIZE) {
			nsegs++;
			sectors += bv.bv_len >> 9;
		} else if (bvec_split_segs(q, &bv, &nsegs, §ors, max_segs,
					 max_sectors)) {
			goto split;
		}

		bvprv = bv;
		bvprvp = &bvprv;
	}

	*segs = nsegs;
	return NULL;
split:
	*segs = nsegs;

	bio_clear_polled(bio);
	return bio_split(bio, sectors, GFP_NOIO, bs);
}

void __blk_queue_split(struct request_queue *q, struct bio **bio,
		       unsigned int *nr_segs)
{
	struct bio *split = NULL;

	switch (bio_op(*bio)) {
	case REQ_OP_DISCARD:
	case REQ_OP_SECURE_ERASE:
		split = blk_bio_discard_split(q, *bio, &q->bio_split, nr_segs);
		break;
	case REQ_OP_WRITE_ZEROES:
		split = blk_bio_write_zeroes_split(q, *bio, &q->bio_split,
				nr_segs);
		break;
	default:
		split = blk_bio_segment_split(q, *bio, &q->bio_split, nr_segs);
		break;
	}

	if (split) {
		split->bi_opf |= REQ_NOMERGE;

		blkcg_bio_issue_init(split);
		bio_chain(split, *bio);
		trace_block_split(split, (*bio)->bi_iter.bi_sector);
		submit_bio_noacct(*bio);
		*bio = split;
	}
}

void blk_queue_split(struct bio **bio)
{
	struct request_queue *q = bdev_get_queue((*bio)->bi_bdev);
	unsigned int nr_segs;

	if (blk_may_split(q, *bio))
		__blk_queue_split(q, bio, &nr_segs);
}
EXPORT_SYMBOL(blk_queue_split);

unsigned int blk_recalc_rq_segments(struct request *rq)
{
	unsigned int nr_phys_segs = 0;
	unsigned int nr_sectors = 0;
	struct req_iterator iter;
	struct bio_vec bv;

	if (!rq->bio)
		return 0;

	switch (bio_op(rq->bio)) {
	case REQ_OP_DISCARD:
	case REQ_OP_SECURE_ERASE:
		if (queue_max_discard_segments(rq->q) > 1) {
			struct bio *bio = rq->bio;

			for_each_bio(bio)
				nr_phys_segs++;
			return nr_phys_segs;
		}
		return 1;
	case REQ_OP_WRITE_ZEROES:
		return 0;
	}

	rq_for_each_bvec(bv, rq, iter)
		bvec_split_segs(rq->q, &bv, &nr_phys_segs, &nr_sectors,
				UINT_MAX, UINT_MAX);
	return nr_phys_segs;
}

static inline struct scatterlist *blk_next_sg(struct scatterlist **sg,
		struct scatterlist *sglist)
{
	if (!*sg)
		return sglist;

	sg_unmark_end(*sg);
	return sg_next(*sg);
}

static unsigned blk_bvec_map_sg(struct request_queue *q,
		struct bio_vec *bvec, struct scatterlist *sglist,
		struct scatterlist **sg)
{
	unsigned nbytes = bvec->bv_len;
	unsigned nsegs = 0, total = 0;

	while (nbytes > 0) {
		unsigned offset = bvec->bv_offset + total;
		unsigned len = min(get_max_segment_size(q, bvec->bv_page,
					offset), nbytes);
		struct page *page = bvec->bv_page;

		page += (offset >> PAGE_SHIFT);
		offset &= ~PAGE_MASK;

		*sg = blk_next_sg(sg, sglist);
		sg_set_page(*sg, page, len, offset);

		total += len;
		nbytes -= len;
		nsegs++;
	}

	return nsegs;
}

static inline int __blk_bvec_map_sg(struct bio_vec bv,
		struct scatterlist *sglist, struct scatterlist **sg)
{
	*sg = blk_next_sg(sg, sglist);
	sg_set_page(*sg, bv.bv_page, bv.bv_len, bv.bv_offset);
	return 1;
}

static inline bool
__blk_segment_map_sg_merge(struct request_queue *q, struct bio_vec *bvec,
			   struct bio_vec *bvprv, struct scatterlist **sg)
{

	int nbytes = bvec->bv_len;

	if (!*sg)
		return false;

	if ((*sg)->length + nbytes > queue_max_segment_size(q))
		return false;

	if (!biovec_phys_mergeable(q, bvprv, bvec))
		return false;

	(*sg)->length += nbytes;

	return true;
}

static int __blk_bios_map_sg(struct request_queue *q, struct bio *bio,
			     struct scatterlist *sglist,
			     struct scatterlist **sg)
{
	struct bio_vec bvec, bvprv = { NULL };
	struct bvec_iter iter;
	int nsegs = 0;
	bool new_bio = false;

	for_each_bio(bio) {
		bio_for_each_bvec(bvec, bio, iter) {
			if (new_bio &&
			    __blk_segment_map_sg_merge(q, &bvec, &bvprv, sg))
				goto next_bvec;

			if (bvec.bv_offset + bvec.bv_len <= PAGE_SIZE)
				nsegs += __blk_bvec_map_sg(bvec, sglist, sg);
			else
				nsegs += blk_bvec_map_sg(q, &bvec, sglist, sg);
 next_bvec:
			new_bio = false;
		}
		if (likely(bio->bi_iter.bi_size)) {
			bvprv = bvec;
			new_bio = true;
		}
	}

	return nsegs;
}

int __blk_rq_map_sg(struct request_queue *q, struct request *rq,
		struct scatterlist *sglist, struct scatterlist **last_sg)
{
	int nsegs = 0;

	if (rq->rq_flags & RQF_SPECIAL_PAYLOAD)
		nsegs = __blk_bvec_map_sg(rq->special_vec, sglist, last_sg);
	else if (rq->bio)
		nsegs = __blk_bios_map_sg(q, rq->bio, sglist, last_sg);

	if (*last_sg)
		sg_mark_end(*last_sg);

	WARN_ON(nsegs > blk_rq_nr_phys_segments(rq));

	return nsegs;
}
EXPORT_SYMBOL(__blk_rq_map_sg);

static inline unsigned int blk_rq_get_max_segments(struct request *rq)
{
	if (req_op(rq) == REQ_OP_DISCARD)
		return queue_max_discard_segments(rq->q);
	return queue_max_segments(rq->q);
}

static inline unsigned int blk_rq_get_max_sectors(struct request *rq,
						  sector_t offset)
{
	struct request_queue *q = rq->q;

	if (blk_rq_is_passthrough(rq))
		return q->limits.max_hw_sectors;

	if (!q->limits.chunk_sectors ||
	    req_op(rq) == REQ_OP_DISCARD ||
	    req_op(rq) == REQ_OP_SECURE_ERASE)
		return blk_queue_get_max_sectors(q, req_op(rq));

	return min(blk_max_size_offset(q, offset, 0),
			blk_queue_get_max_sectors(q, req_op(rq)));
}

static inline int ll_new_hw_segment(struct request *req, struct bio *bio,
		unsigned int nr_phys_segs)
{
	if (!blk_cgroup_mergeable(req, bio))
		goto no_merge;

	if (blk_integrity_merge_bio(req->q, req, bio) == false)
		goto no_merge;

	if (req_op(req) == REQ_OP_DISCARD)
		return 1;

	if (req->nr_phys_segments + nr_phys_segs > blk_rq_get_max_segments(req))
		goto no_merge;

	req->nr_phys_segments += nr_phys_segs;
	return 1;

no_merge:
	req_set_nomerge(req->q, req);
	return 0;
}

int ll_back_merge_fn(struct request *req, struct bio *bio, unsigned int nr_segs)
{
	if (req_gap_back_merge(req, bio))
		return 0;
	if (blk_integrity_rq(req) &&
	    integrity_req_gap_back_merge(req, bio))
		return 0;
	if (!bio_crypt_ctx_back_mergeable(req, bio))
		return 0;
	if (blk_rq_sectors(req) + bio_sectors(bio) >
	    blk_rq_get_max_sectors(req, blk_rq_pos(req))) {
		req_set_nomerge(req->q, req);
		return 0;
	}

	return ll_new_hw_segment(req, bio, nr_segs);
}

static int ll_front_merge_fn(struct request *req, struct bio *bio,
		unsigned int nr_segs)
{
	if (req_gap_front_merge(req, bio))
		return 0;
	if (blk_integrity_rq(req) &&
	    integrity_req_gap_front_merge(req, bio))
		return 0;
	if (!bio_crypt_ctx_front_mergeable(req, bio))
		return 0;
	if (blk_rq_sectors(req) + bio_sectors(bio) >
	    blk_rq_get_max_sectors(req, bio->bi_iter.bi_sector)) {
		req_set_nomerge(req->q, req);
		return 0;
	}

	return ll_new_hw_segment(req, bio, nr_segs);
}

static bool req_attempt_discard_merge(struct request_queue *q, struct request *req,
		struct request *next)
{
	unsigned short segments = blk_rq_nr_discard_segments(req);

	if (segments >= queue_max_discard_segments(q))
		goto no_merge;
	if (blk_rq_sectors(req) + bio_sectors(next->bio) >
	    blk_rq_get_max_sectors(req, blk_rq_pos(req)))
		goto no_merge;

	req->nr_phys_segments = segments + blk_rq_nr_discard_segments(next);
	return true;
no_merge:
	req_set_nomerge(q, req);
	return false;
}

static int ll_merge_requests_fn(struct request_queue *q, struct request *req,
				struct request *next)
{
	int total_phys_segments;

	if (req_gap_back_merge(req, next->bio))
		return 0;

	if ((blk_rq_sectors(req) + blk_rq_sectors(next)) >
	    blk_rq_get_max_sectors(req, blk_rq_pos(req)))
		return 0;

	total_phys_segments = req->nr_phys_segments + next->nr_phys_segments;
	if (total_phys_segments > blk_rq_get_max_segments(req))
		return 0;

	if (!blk_cgroup_mergeable(req, next->bio))
		return 0;

	if (blk_integrity_merge_rq(q, req, next) == false)
		return 0;

	if (!bio_crypt_ctx_merge_rq(req, next))
		return 0;

	req->nr_phys_segments = total_phys_segments;
	return 1;
}

void blk_rq_set_mixed_merge(struct request *rq)
{
	unsigned int ff = rq->cmd_flags & REQ_FAILFAST_MASK;
	struct bio *bio;

	if (rq->rq_flags & RQF_MIXED_MERGE)
		return;

	for (bio = rq->bio; bio; bio = bio->bi_next) {
		WARN_ON_ONCE((bio->bi_opf & REQ_FAILFAST_MASK) &&
			     (bio->bi_opf & REQ_FAILFAST_MASK) != ff);
		bio->bi_opf |= ff;
	}
	rq->rq_flags |= RQF_MIXED_MERGE;
}

static void blk_account_io_merge_request(struct request *req)
{
	if (blk_do_io_stat(req)) {
		part_stat_lock();
		part_stat_inc(req->part, merges[op_stat_group(req_op(req))]);
		part_stat_unlock();
	}
}

static enum elv_merge blk_try_req_merge(struct request *req,
					struct request *next)
{
	if (blk_discard_mergable(req))
		return ELEVATOR_DISCARD_MERGE;
	else if (blk_rq_pos(req) + blk_rq_sectors(req) == blk_rq_pos(next))
		return ELEVATOR_BACK_MERGE;

	return ELEVATOR_NO_MERGE;
}

static struct request *attempt_merge(struct request_queue *q,
				     struct request *req, struct request *next)
{
	if (!rq_mergeable(req) || !rq_mergeable(next))
		return NULL;

	if (req_op(req) != req_op(next))
		return NULL;

	if (rq_data_dir(req) != rq_data_dir(next))
		return NULL;

	if (req->ioprio != next->ioprio)
		return NULL;


	switch (blk_try_req_merge(req, next)) {
	case ELEVATOR_DISCARD_MERGE:
		if (!req_attempt_discard_merge(q, req, next))
			return NULL;
		break;
	case ELEVATOR_BACK_MERGE:
		if (!ll_merge_requests_fn(q, req, next))
			return NULL;
		break;
	default:
		return NULL;
	}

	if (((req->rq_flags | next->rq_flags) & RQF_MIXED_MERGE) ||
	    (req->cmd_flags & REQ_FAILFAST_MASK) !=
	    (next->cmd_flags & REQ_FAILFAST_MASK)) {
		blk_rq_set_mixed_merge(req);
		blk_rq_set_mixed_merge(next);
	}

	if (next->start_time_ns < req->start_time_ns)
		req->start_time_ns = next->start_time_ns;

	req->biotail->bi_next = next->bio;
	req->biotail = next->biotail;

	req->__data_len += blk_rq_bytes(next);

	if (!blk_discard_mergable(req))
		elv_merge_requests(q, req, next);

	blk_account_io_merge_request(next);

	trace_block_rq_merge(next);

	next->bio = NULL;
	return next;
}

static struct request *attempt_back_merge(struct request_queue *q,
		struct request *rq)
{
	struct request *next = elv_latter_request(q, rq);

	if (next)
		return attempt_merge(q, rq, next);

	return NULL;
}

static struct request *attempt_front_merge(struct request_queue *q,
		struct request *rq)
{
	struct request *prev = elv_former_request(q, rq);

	if (prev)
		return attempt_merge(q, prev, rq);

	return NULL;
}

bool blk_attempt_req_merge(struct request_queue *q, struct request *rq,
			   struct request *next)
{
	return attempt_merge(q, rq, next);
}

bool blk_rq_merge_ok(struct request *rq, struct bio *bio)
{
	if (!rq_mergeable(rq) || !bio_mergeable(bio))
		return false;

	if (req_op(rq) != bio_op(bio))
		return false;

	if (bio_data_dir(bio) != rq_data_dir(rq))
		return false;

	if (!blk_cgroup_mergeable(rq, bio))
		return false;

	if (blk_integrity_merge_bio(rq->q, rq, bio) == false)
		return false;

	if (!bio_crypt_rq_ctx_compatible(rq, bio))
		return false;

	if (rq->ioprio != bio_prio(bio))
		return false;

	return true;
}

enum elv_merge blk_try_merge(struct request *rq, struct bio *bio)
{
	if (blk_discard_mergable(rq))
		return ELEVATOR_DISCARD_MERGE;
	else if (blk_rq_pos(rq) + blk_rq_sectors(rq) == bio->bi_iter.bi_sector)
		return ELEVATOR_BACK_MERGE;
	else if (blk_rq_pos(rq) - bio_sectors(bio) == bio->bi_iter.bi_sector)
		return ELEVATOR_FRONT_MERGE;
	return ELEVATOR_NO_MERGE;
}

static void blk_account_io_merge_bio(struct request *req)
{
	if (!blk_do_io_stat(req))
		return;

	part_stat_lock();
	part_stat_inc(req->part, merges[op_stat_group(req_op(req))]);
	part_stat_unlock();
}

enum bio_merge_status {
	BIO_MERGE_OK,
	BIO_MERGE_NONE,
	BIO_MERGE_FAILED,
};

static enum bio_merge_status bio_attempt_back_merge(struct request *req,
		struct bio *bio, unsigned int nr_segs)
{
	const int ff = bio->bi_opf & REQ_FAILFAST_MASK;

	if (!ll_back_merge_fn(req, bio, nr_segs))
		return BIO_MERGE_FAILED;

	trace_block_bio_backmerge(bio);
	rq_qos_merge(req->q, req, bio);

	if ((req->cmd_flags & REQ_FAILFAST_MASK) != ff)
		blk_rq_set_mixed_merge(req);

	req->biotail->bi_next = bio;
	req->biotail = bio;
	req->__data_len += bio->bi_iter.bi_size;

	bio_crypt_free_ctx(bio);

	blk_account_io_merge_bio(req);
	return BIO_MERGE_OK;
}

static enum bio_merge_status bio_attempt_front_merge(struct request *req,
		struct bio *bio, unsigned int nr_segs)
{
	const int ff = bio->bi_opf & REQ_FAILFAST_MASK;

	if (!ll_front_merge_fn(req, bio, nr_segs))
		return BIO_MERGE_FAILED;

	trace_block_bio_frontmerge(bio);
	rq_qos_merge(req->q, req, bio);

	if ((req->cmd_flags & REQ_FAILFAST_MASK) != ff)
		blk_rq_set_mixed_merge(req);

	bio->bi_next = req->bio;
	req->bio = bio;

	req->__sector = bio->bi_iter.bi_sector;
	req->__data_len += bio->bi_iter.bi_size;

	bio_crypt_do_front_merge(req, bio);

	blk_account_io_merge_bio(req);
	return BIO_MERGE_OK;
}

static enum bio_merge_status bio_attempt_discard_merge(struct request_queue *q,
		struct request *req, struct bio *bio)
{
	unsigned short segments = blk_rq_nr_discard_segments(req);

	if (segments >= queue_max_discard_segments(q))
		goto no_merge;
	if (blk_rq_sectors(req) + bio_sectors(bio) >
	    blk_rq_get_max_sectors(req, blk_rq_pos(req)))
		goto no_merge;

	rq_qos_merge(q, req, bio);

	req->biotail->bi_next = bio;
	req->biotail = bio;
	req->__data_len += bio->bi_iter.bi_size;
	req->nr_phys_segments = segments + 1;

	blk_account_io_merge_bio(req);
	return BIO_MERGE_OK;
no_merge:
	req_set_nomerge(q, req);
	return BIO_MERGE_FAILED;
}

static enum bio_merge_status blk_attempt_bio_merge(struct request_queue *q,
						   struct request *rq,
						   struct bio *bio,
						   unsigned int nr_segs,
						   bool sched_allow_merge)
{
	if (!blk_rq_merge_ok(rq, bio))
		return BIO_MERGE_NONE;

	switch (blk_try_merge(rq, bio)) {
	case ELEVATOR_BACK_MERGE:
		if (!sched_allow_merge || blk_mq_sched_allow_merge(q, rq, bio))
			return bio_attempt_back_merge(rq, bio, nr_segs);
		break;
	case ELEVATOR_FRONT_MERGE:
		if (!sched_allow_merge || blk_mq_sched_allow_merge(q, rq, bio))
			return bio_attempt_front_merge(rq, bio, nr_segs);
		break;
	case ELEVATOR_DISCARD_MERGE:
		return bio_attempt_discard_merge(q, rq, bio);
	default:
		return BIO_MERGE_NONE;
	}

	return BIO_MERGE_FAILED;
}

bool blk_attempt_plug_merge(struct request_queue *q, struct bio *bio,
		unsigned int nr_segs)
{
	struct blk_plug *plug;
	struct request *rq;

	plug = blk_mq_plug(q, bio);
	if (!plug || rq_list_empty(plug->mq_list))
		return false;

	rq_list_for_each(&plug->mq_list, rq) {
		if (rq->q == q) {
			if (blk_attempt_bio_merge(q, rq, bio, nr_segs, false) ==
			    BIO_MERGE_OK)
				return true;
			break;
		}

		if (!plug->multiple_queues)
			break;
	}
	return false;
}

bool blk_bio_list_merge(struct request_queue *q, struct list_head *list,
			struct bio *bio, unsigned int nr_segs)
{
	struct request *rq;
	int checked = 8;

	list_for_each_entry_reverse(rq, list, queuelist) {
		if (!checked--)
			break;

		switch (blk_attempt_bio_merge(q, rq, bio, nr_segs, true)) {
		case BIO_MERGE_NONE:
			continue;
		case BIO_MERGE_OK:
			return true;
		case BIO_MERGE_FAILED:
			return false;
		}

	}

	return false;
}
EXPORT_SYMBOL_GPL(blk_bio_list_merge);

bool blk_mq_sched_try_merge(struct request_queue *q, struct bio *bio,
		unsigned int nr_segs, struct request **merged_request)
{
	struct request *rq;

	switch (elv_merge(q, &rq, bio)) {
	case ELEVATOR_BACK_MERGE:
		if (!blk_mq_sched_allow_merge(q, rq, bio))
			return false;
		if (bio_attempt_back_merge(rq, bio, nr_segs) != BIO_MERGE_OK)
			return false;
		*merged_request = attempt_back_merge(q, rq);
		if (!*merged_request)
			elv_merged_request(q, rq, ELEVATOR_BACK_MERGE);
		return true;
	case ELEVATOR_FRONT_MERGE:
		if (!blk_mq_sched_allow_merge(q, rq, bio))
			return false;
		if (bio_attempt_front_merge(rq, bio, nr_segs) != BIO_MERGE_OK)
			return false;
		*merged_request = attempt_front_merge(q, rq);
		if (!*merged_request)
			elv_merged_request(q, rq, ELEVATOR_FRONT_MERGE);
		return true;
	case ELEVATOR_DISCARD_MERGE:
		return bio_attempt_discard_merge(q, rq, bio) == BIO_MERGE_OK;
	default:
		return false;
	}
}
EXPORT_SYMBOL_GPL(blk_mq_sched_try_merge);