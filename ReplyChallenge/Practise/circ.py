MEMORY = 'a_cdefaijkltmnopwzstueabez01200067890ABCDEFGHIJKnooodtdvw000eta?T!VW00Y!ETA?*-+/{}[]=&%£"!()abcdefghijklmnopqrsABCDEFGHIJKLNMuuuvwxipsilonnnnnnz%%/9876543210|!"£$ohdear!%&/(((()*;:_AAAABSIDEOWabcdefghijklmnopqrstuvwxyz012345678?8?8?8?9!!!!!EGIN.CERTIFICATEa_cdefaijkltmnopwzstueabez01200067890ABCDEFGHIJKnooodtdvw000eta?T!VW00Y!ETA?*-+/{}[]=&%£"!()abcdefghijklmnopqrsABCDEFGHIJKLNMuuuvwxipsilonnnnnnz%%/9876543210|!"£$ohdear!%&/(((()*;:_AAAABSIDEOWabcdefghijklmnopqrstuvwxyz012345678?8?8?8?9!!!!!EGIN.CERTIFICATE'

def circuit(input):
    output = [0,0,0,0,0,0,0,0,0]
    out_num = ""
    output[0] = input[0] ^ (input[3] ^ input[8])
    output[1] = input[1] & input[7]
    output[2] = input[3] ^ input[8]
    output[3] = input[8]
    output[4] = input[8] | (not input[3]) | adder(input[5], input[4], input[6])[0]
    output[5] = adder(input[5], input[4], input[6])[0]
    output[6] = input[2] ^ adder(input[5], input[4], input[6])[1]
    output[7] = input[3]
    output[8] = input[0] ^ (input[2] ^ adder(input[5], input[4], input[6])[1])
    for i in range(len(output)):
        output[i] = int(output[i])
        out_num += str(output[i])
    return output, int(out_num, 2)

def adder(a, b, c):
    total = a + b + c
    if total == 0:
        return [0, 0]
    elif total == 1:
        return [1, 0]
    elif total == 2:
        return [0, 1]
    elif total == 3:
        return [1, 1]

in_bin = [0,0,0,0,0,0,0,0,0]
c = 0
result = ""
while len(result) < 10: 
    out_bin, location = circuit(in_bin)
    result += MEMORY[location]
    in_bin = out_bin
    c += 1

print("{FLG:" + result + "}")

    