
## BLACK-LIST  OR  WHITELIST OF MAC

----------------------
Command to Add to denylist-clients to Aruba Wireless Controllers..

[mynode] #stm add-denylist-client aabbccddffgg

----------------------

Command to Remove specific MAC from from denylist-clients on Aruba Wireless Controllers..

[mynode] #stm remove-denylist-client aabbccddffgg

----------------------

VERIFY :

[mynode] #show ap denylist-clients | include aa:bb:cc:dd:ee:ff

aa:bb:cc:dd:ee:ff  user-defined  490              Permanent

------------------------------------------------------------------------------------------------------
