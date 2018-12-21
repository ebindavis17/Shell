list1 = [ '2C535EB58F19B58','7B89D9071EB531B143594FF909BAC846','0509', '02c535eb58f19b58' ]

list2  = [ '1641AB0C9C5B8867' , '0098968C' , '509', '2c535eb58f19b58' ]

res = [x for x in list2 if any(y for y in list1 if x in y)]
#print(res)
print(list1)
#print(s[1:] )
for i in list1 :
   print( i[1:] if i.startswith('0') else i )
