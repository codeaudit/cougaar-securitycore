Database = jdbc:postgresql:${icis.database}
headerQuery=select commodity, nsn, NOMENCLATURE, ui, ssc, price, icc, alt, plt, pcm, boq, diq, iaq, nso, qfd, rop, owrmrp, weight, cube, aac, slq from header where NSN = :nsn
assetsQuery=select nsn, ric, purpose, condition, iaq from assets where NSN = :nsn
nomen=select nomenclature from header where NSN = :nsn	
cost=select price from header where NSN = :nsn
volume=select cube from header where NSN = :nsn
weight=select weight from header where NSN = :nsn
classIXData=select NOMENCLATURE, ui, price, cube, weight from header where NSN = :nsn 
classVData=select NOMENCLATURE, weight, ccc from ammo_characteristics where DODIC = :nsn
ui=select ui from header where NSN = :nsn
DLAInventory=select IAQ from header where NSN = :nsn
# MEI
#
meiQuery=select NOMENCLATURE from aggregated_mei_nomenclature where MEI = :nsn and SERVICE = :service
# ARMY
#
ConsumableArmyNSN=select MEI_NSN, PART_NSN, OPTEMPO, DCR from army_spares_dcr_by_optempo where MEI_NSN = :nsn
#BulkPOLArmyNSN=select NSN, FUEL_NSN, OPTEMPO, GALLONS_PER_DAY from army_fuels_dcr_by_optempo where NSN = :nsn
BulkPOLArmyNSN=select NSN, FUEL_NSN, OPTEMPO, GALLONS_PER_DAY from alp_mei_fuel where NSN = :nsn
AmmunitionArmyNSN=select MEI_NSN, DODIC, OPTEMPO, TONS_PER_DAY from alp_mei_dodic_2_view where MEI_NSN = :nsn
# AirForce
#
ConsumableAirforceMDS=select MDS, NSN, OPTEMPO, DEMANDS_PER_DAY from airforce_spares_dcr_by_optempo where MDS = :nsn
BulkPOLAirforceMDS=select MDS, FUEL_NSN, OPTEMPO, GALLONS_PER_DAY from airforce_fuels_dcr_by_optempo where MDS = :nsn
# Marine
# 
ConsumableMarineTAMCN=select TAMCN, PART_NSN, OPTEMPO, DCR from mcgrd_spares_dcr_by_optempo where TAMCN = :nsn
ConsumableMarineNSN=select MEI_NSN, PART_NSN, OPTEMPO, DCR from mcgrd_spares_dcr_by_optempo where MEI_NSN = :nsn
ConsumableMarineMDS=select MDS,NSN, OPTEMPO, DEMANDS_PER_DAY from usmcair_spares_dcr_by_optempo where MDS = :nsn
BulkPOLMarineTAMCN=select TAMCN, FUEL_NSN, OPTEMPO, GALLONS_PER_DAY from marine_ground_fuels_dcr_by_op where TAMCN = :nsn 
BulkPOLMarineMDS=select MDS, FUEL_NSN, OPTEMPO, GALLONS_PER_DAY from marine_air_fuels_dcr_by_op where MDS = :nsn
# Navy
#
ConsumableNavyMEI=select MEI_ID, NSN, OPTEMPO, DCR from navy_spares_dcr_by_optempo where MEI_ID = :nsn
ConsumableNavyMDS=select MDS, NSN, OPTEMPO, DEMANDS_PER_DAY from navyair_spares_dcr_by_optempo where MDS = :nsn
# Prototype & Property Provider
#
%com.bbn.supply.plugins.IcisPrototypeProvider
%com.bbn.supply.plugins.IcisPropertyProvider
