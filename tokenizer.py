#!/usr/bin/python3
from token_types import C_lang, Python_lang
import sys
file_name = sys.argv[1]

def tokenize(s,token_types,allowed):
    word = ""
    # tokens = []
    i = 0
    while i < len(s):
        c = s[i]
        if c in token_types:
            yield (c,token_types[c])
            # tokens.append((c,token_types[c]))
            i = i + 1
            continue

        for j in range(i,len(s)):
            if s[j] == "|":
                print(word)
            if s[j] == "\n" or s[j] == " ":
                i = j + 1
                break
            if s[j].isalnum() or s[j] in allowed:
                word = word + s[j]
                i = j + 1
            if word in token_types:
                i = j + 1
                break
            if s[j] in token_types:
                i = j
                break
        
        if word != "":
            if word in token_types:
                yield (word,token_types[word])
                # tokens.append((word,token_types[word]))
            else:
                yield (word,"Word")
                # tokens.append((word,"Word"))
                
        word = ""
    
    # for tok in tokens:
    #     print(tok)


tok_dct = {}
if file_name.endswith("py"):
    tok_dct = Python_lang
if file_name.endswith("c"):
    tok_dct = C_lang

file_content = ""
with open(file_name,"r") as f:
    file_content = f.read()

# s = "((27/2)+2+{23+22}-10)*3"
# file_content = s

allowed_in_a_word = [".","_"]  # + list(tok_dct.keys())

count = 0
z     = tokenize(file_content,tok_dct,allowed_in_a_word)

while True:
    try:
        count = count + 1
        # token, typ = next(z)
        # if typ == "Word":
            # print(token)
        print(next(z))
        # print(token)
    except StopIteration:
        break

print(count)