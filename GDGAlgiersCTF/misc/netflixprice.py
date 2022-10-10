import csv
import hashlib

ghost = 74545
harry = 88125

with open('ratings.csv.part','r') as fin:
    with open('possible_ghost.csv','w') as fout1:
        with open('possible_harry.csv','w') as fout2:
            writer1 = csv.writer(fout1, delimiter=';')
            writer2 = csv.writer(fout2, delimiter=';')
            reader = csv.reader(fin, delimiter=';')
            next(reader)
            for row in reader:
                if float(row[1]) == ghost and 4841 < float(row[3]) < 5206:
                    writer1.writerow(row)
                if float(row[1]) == harry and 4944 < float(row[3]) < 4966:
                    writer2.writerow(row)

pos1 = []
pos2 = []

with open('possible_harry.csv','r') as fin1:
    with open('possible_ghost.csv','r') as fin2:
        reader1 = csv.reader(fin1, delimiter=';')
        reader2 = csv.reader(fin2, delimiter=';')
        for row in reader1:
            pos1.append(int(row[0]))
        for row in reader2:
            pos2.append(int(row[0]))

for a in pos1:
    if a in pos2:
        print(a)
        print(hashlib.md5(str(a).encode()).hexdigest())
