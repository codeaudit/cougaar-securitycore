Database=jdbc:postgresql:${org.cougaar.database}
Driver = org.postgresql.Driver
Username = ${blackjack.database.user}
Password = ${blackjack.database.password}
MIN_IN_POOL= 1
MAX_IN_POOL= 4
TIMEOUT= 1
NUMBER_OF_TRIES= 2



ClassIData=select "NOMENCLATURE", "MEAL_TYPE", "UI", "ROTATION_DAY", "WEIGHT", "ALTERNATE_NAME", "COUNT_PER_UI", "UNIT_OF_PACK", "VOL_CUBIC_FEET", "COST" from class1_item where  "NSN" = :nsns

ClassIMenuList = select "NSN", "NOMENCLATURE", "ROTATION_DAY" from class1_item where "MEAL_TYPE" = :meal and "NOMENCLATURE" = :nomn order by "ROTATION_DAY"

ClassISupplementList = select "SUPPLEMENT_ITEM_NSN",  "SUPPLEMENT_ITEM_RATE" from class1_supplement_rate where "MEAL_TYPE" = :meal and "ALTERNATE_NAME" = :nomn

Class1ConsumedList = select "NSN" from class1_item
