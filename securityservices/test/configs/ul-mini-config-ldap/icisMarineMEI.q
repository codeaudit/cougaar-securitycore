Driver = org.postgresql.Driver
Database=jdbc:postgresql:${marine.database}
Username = ${marine.database.supply.user}
Password = ${marine.database.supply.password}
MIN_IN_POOL= 1
MAX_IN_POOL= 4
TIMEOUT= 1
NUMBER_OF_TRIES= 2

headerQuery=select commodity, nsn, NOMENCLATURE, ui, ssc, price, icc, alt, plt, pcm, boq, diq, iaq, nso, qfd, rop, owrmrp, weight, cube, aac, slq from header where NSN = :nsn
assetsQuery=select nsn, ric, purpose, condition, iaq from assets where NSN = :nsn
nomen=select nomenclature from header where NSN = :nsn	
cost=select price from header where NSN = :nsn
volume=select cube from header where NSN = :nsn
weight=select weight from header where NSN = :nsn
classIXData=select NOMENCLATURE, ui, price, cube, weight from header where NSN = :nsn 
classVData=select NOMENCLATURE, weight, ccc from ammo_characteristics where DODIC = :nsn
ui=select ui from header where NSN = :nsn
# MEI
#
meiQuery=select NOMENCLATURE from aggregated_mei_nomenclature where MEI = :nsn and SERVICE = :service
# Marine
 
# ==>BulkPOL (Fuels)
BulkPOLMarineNSN=select T.NSN, FUEL_NSN, OPTEMPO, GALLONS_PER_DAY from marine_ground_fuels_dcr_by_op M, tamcn_nsn_map T where M.TAMCN = T.TAMCN and NSN = :nsn order by GALLONS_PER_DAY
BulkPOLMarineTAMCN=select TAMCN, FUEL_NSN, OPTEMPO, GALLONS_PER_DAY from marine_ground_fuels_dcr_by_op where TAMCN = :nsn order by GALLONS_PER_DAY
BulkPOLMarineMDS=select T.NSN, FUEL_NSN, OPTEMPO, GALLONS_PER_DAY from marine_air_fuels_dcr_by_op M, tamcn_nsn_map T  where M.MDS = T.TAMCN and NSN = :nsn order by GALLONS_PER_DAY

# ==>Ammunition
AmmunitionMarineNSN=select MEI_NSN, DODIC, OPTEMPO, TONS_PER_DAY from alp_mei_dodic_2_view where MEI_NSN = :nsn order by TONS_PER_DAY
AmmunitionMarineMDS=select MEI_NSN, DODIC, OPTEMPO, TONS_PER_DAY from alp_mei_dodic_2_view where MEI_NSN = :nsn order by TONS_PER_DAY

# ==>Consumable (Critical Spare Parts)
ConsumableMarineTAMCN=select TAMCN, PART_NSN, OPTEMPO, DCR from mcgrd_spares_dcr_by_optempo where TAMCN = :nsn order by DCR
ConsumableMarineNSN=select MEI_NSN, PART_NSN, OPTEMPO, DCR from mcgrd_spares_dcr_by_optempo where MEI_NSN = :nsn order by DCR
ConsumableMarineMDS=select MDS,NSN, OPTEMPO, DEMANDS_PER_DAY from usmcair_spares_dcr_by_optempo where MDS = :nsn order by DEMANDS_PER_DAY
