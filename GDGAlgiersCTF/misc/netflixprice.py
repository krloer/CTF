import csv
import hashlib

with open('ratings.csv.part','r') as fin:
    with open('possible_fool.csv','w') as fout:
        writer = csv.writer(fout, delimiter=';')
        reader = csv.reader(fin, delimiter=';')
        next(reader)
        for row in reader:
            if float(row[2]) >= 2.0 and 2800 < float(row[3]) < 3100:
                writer.writerow(row)

# pos1 = []
# pos2 = []

# with open('possible_harry.csv','r') as fin1:
#     with open('possible_ghost.csv','r') as fin2:
#         reader1 = csv.reader(fin1, delimiter=';')
#         reader2 = csv.reader(fin2, delimiter=';')
#         for row in reader1:
#             pos1.append(int(row[0]))
#         for row in reader2:
#             pos2.append(int(row[0]))

# print(pos1)
# print(pos2)

# for a in pos1:
#     if a in pos2:
#         print(a)
