Database=jdbc:postgresql:${org.cougaar.database}
Driver = org.postgresql.Driver
Username = ${blackjack.database.user}
Password = ${blackjack.database.password}
MIN_IN_POOL= 1
MAX_IN_POOL= 4
TIMEOUT= 1
NUMBER_OF_TRIES= 2

# classVIIIData=select NOMENCLATURE, uoi, price, volume, weight from medical_supplies where NSN = :nsns 
classVIIIData=select NOMENCLATURE, unit_issue, unit_price, pack_cube, pack_weight from catalog_master where NSN = :nsns 
