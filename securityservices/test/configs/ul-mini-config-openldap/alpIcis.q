Database=jdbc:postgresql:${org.cougaar.database}

headerQuery=select commodity, nsn, NOMENCLATURE, ui, ssc, price, icc, alt, plt, pcm, boq, diq, iaq, nso, qfd, rop, owrmrp, weight, cube, aac, slq from header where NSN = :nsns
assetsQuery=select nsn, ric, purpose, condition, iaq from assets where NSN = :nsns
nomen=select nomenclature from header where NSN = :nsns	
cost=select price from header where NSN = :nsns
volume=select cube from header where NSN = :nsns
weight=select weight from header where NSN = :nsns
classIXData=select NOMENCLATURE, ui, price, cube, weight from header where NSN = :nsns 
classVData=select NOMENCLATURE, weight, ccc from ammo_characteristics where DODIC = :nsns
ui=select ui from header where NSN = :nsns
DLAInventory=select IAQ from header where NSN = :nsns
# MEI
#
meiQuery=select NOMENCLATURE from aggregated_mei_nomemclature where MEI = :nsns and SERVICE = :service
# ARMY
#
ConsumableArmyNSN=select MEI_NSN, PART_NSN, OPTEMPO, DCR from army_spares_dcr_by_optempo where MEI_NSN = :nsns
#BulkPOLArmyNSN=select NSN, FUEL_NSN, OPTEMPO, GALLONS_PER_DAY from army_fuels_dcr_by_optempo where NSN = :nsns
BulkPOLArmyNSN=select NSN, FUEL_NSN, OPTEMPO, GALLONS_PER_DAY from alp_mei_fuel where NSN = :nsns
AmmunitionArmyNSN=select MEI_NSN, DODIC, OPTEMPO, TONS_PER_DAY from alp_mei_dodic_2_view where MEI_NSN = :nsns
# AirForce
#
ConsumableAirforceMDS=select MDS, NSN, OPTEMPO, DEMANDS_PER_DAY from airforce_spares_dcr_by_optempo where MDS = :nsns
BulkPOLAirforceMDS=select MDS, FUEL_NSN, OPTEMPO, GALLONS_PER_DAY from airforce_fuels_dcr_by_optempo where MDS = :nsns
# Marine
# 
ConsumableMarineTAMCN=select TAMCN, PART_NSN, OPTEMPO, DCR from mcgrd_spares_dcr_by_optempo where TAMCN = :nsns
ConsumableMarineNSN=select MEI_NSN, PART_NSN, OPTEMPO, DCR from mcgrd_spares_dcr_by_optempo where MEI_NSN = :nsns
ConsumableMarineMDS=select MDS,NSN, OPTEMPO, DEMANDS_PER_DAY from usmcair_spares_dcr_by_optempo where MDS = :nsns
BulkPOLMarineTAMCN=select TAMCN, FUEL_NSN, OPTEMPO, GALLONS_PER_DAY from marine_ground_fuels_dcr_by_op where TAMCN = :nsns 
BulkPOLMarineMDS=select MDS, FUEL_NSN, OPTEMPO, GALLONS_PER_DAY from marine_air_fuels_dcr_by_op where MDS = :nsns
# Navy
#
ConsumableNavyMEI=select MEI_ID, NSN, OPTEMPO, DCR from navy_spares_dcr_by_optempo where MEI_ID = :nsns
ConsumableNavyMDS=select MDS, NSN, OPTEMPO, DEMANDS_PER_DAY from navyair_spares_dcr_by_optempo where MDS = :nsns
# Prototype & Property Provider
#
%com.bbn.supply.plugins.IcisPrototypeProvider
%com.bbn.supply.plugins.IcisPropertyProvider
