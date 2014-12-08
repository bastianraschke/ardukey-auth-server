
import re



result = re.search('^[cbdefghijklnrtuv]{0,16}[cbdefghijklnrtuv]{32}$', 'clhbvedrgtnfzubdnivcnblugglkrbcjdeuijivfjkddg')

if ( result ):
    print 'jo'
else:
    print 'no'

print(result)
