Database=jdbc:postgresql:${org.cougaar.database}
Driver = org.postgresql.Driver
Username = ${icis.database.user}
Password = ${icis.database.password}
MIN_IN_POOL= 1
MAX_IN_POOL= 4
TIMEOUT= 1
NUMBER_OF_TRIES= 2

headerQuery=select "COMMODITY", "NSN", "NOMENCLATURE", "UI", "SSC", "PRICE", "ICC", "ALT", "PLT", "PCM", "BOQ", "DIQ", "IAQ", "NSO", "QFD", "ROP", "OWRMRP", "WEIGHT", "CUBE", "AAC", "SLQ" from header where "NSN" = :nsn
assetsQuery=select "NSN", "RIC", "PURPOSE", "CONDITION", "IAQ" from assets where "NSN" = :nsn
nomen=select "NOMENCLATURE" from header where "NSN" = :nsn	
cost=select "PRICE" from header where "NSN" = :nsn
volume=select "CUBE" from header where "NSN" = :nsn
weight=select "WEIGHT" from header where "NSN" = :nsn
classIXData=select "NOMENCLATURE", "UI", "PRICE", "CUBE", "WEIGHT" from header where "NSN" = :nsn 
classIIIPackagedData=select "NOMENCLATURE", "UI", "PRICE", "CUBE", "WEIGHT" from header where "NSN" = :nsn 
classVData=select "NOMENCLATURE", "WEIGHT", "CCC" from ammo_characteristics where "DODIC" = :nsn
ui=select "UI" from header where "NSN" = :nsn
packagedPOLQuery=select "PACKAGED_NSN" from army_packaged_dcr_by_optempo where "PACKAGED_NSN" = :nsn
