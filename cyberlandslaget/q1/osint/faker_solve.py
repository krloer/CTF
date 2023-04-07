import csv

def checkLuhn(cardNo): #geeksforgeeks
     
    nDigits = len(cardNo)
    nSum = 0
    isSecond = False
     
    for i in range(nDigits - 1, -1, -1):
        d = ord(cardNo[i]) - ord('0')
     
        if (isSecond == True):
            d = d * 2
  
        # We add two digits to handle
        # cases that make two digits after
        # doubling
        nSum += d // 10
        nSum += d % 10
  
        isSecond = not isSecond
     
    if (nSum % 10 == 0):
        return True
    else:
        return False

def valid_credit_card_number(credit_card_number):
    if checkLuhn(str(credit_card_number)):
        return True
    return False

def valid_kid_number(kid_number):
    if checkLuhn(str(kid_number)):
        return True
    return False

with open("faker_data.txt") as csvfile:
    reader = csv.DictReader(csvfile)

    for row in reader:
        # The credit card number as an integer
        credit_card_number = int(row["ccNo"])
        
        # The KID number for the last bill paid
        bill_kid = int(row["lastBillKID"])
        
        # If both of these are valid, we're good!
        if valid_credit_card_number(credit_card_number) and valid_kid_number(bill_kid):
           print(f"The hacker must be {row['firstName']} {row['lastName']}!")
           print(f"The flag is flag{{{row['userid']}}}")
        