# First, get the PERSONNEL and generate an aggregate asset
%SQLAggregateAssetCreator
DB_NAME1 = jdbc:postgresql:${org.cougaar.database}
query1 = select 'Personnel' AS NSN, PERSONNEL AS QTY_OH, 'MilitaryPersonnel' AS NOMENCLATURE \
	from ue_summary_mtmc \
    	where UIC = :uic

# Then, get the containers and generate an aggregate asset
%SQLAggregateAssetCreator
DB_NAME1 = jdbc:postgresql:${org.cougaar.database}
query1 = select '8115001682275' AS NSN, container_20_ft_qty AS QTY_OH, 'Container' AS NOMENCLATURE \
	from ue_summary_mtmc \
	where UIC = :uic

# Make sure that all the assets we create use this to fill in consumption rates
#Database=jdbc:postgresql:amp-test2:1521:dart8i
DB_NAME2=jdbc:postgresql:${org.cougaar.database}
headerQuery=select commodity, nsn, NOMENCLATURE, ui, ssc, price, icc, alt, plt, pcm, boq, diq, iaq, nso, qfd, rop, owrmrp, weight, cube, aac, slq from header where NSN = :nsns
assetsQuery=select nsn, ric, purpose, condition, iaq from assets where NSN = :nsns
nomen=select nomenclature from header where NSN = :nsns	
cost=select price from header where NSN = :nsns
# MEI
#
meiQuery=select NOMENCLATURE from aggregated_mei_nomemclature where MEI = :nsns and SERVICE = :service
# ARMY
#
ConsumableArmyNSN=select MEI_NSN, PART_NSN, OPTEMPO, DCR from army_spares_dcr_by_optempo where MEI_NSN = :nsns
BulkPOLArmyNSN=select NSN, FUEL_NSN, OPTEMPO, GALLONS_PER_DAY from army_fuels_dcr_by_optempo where NSN = :nsns
# AirForce
#
ConsumableAirforceMDS=select MDS, NSN, OPTEMPO, DEMANDS_PER_DAY from airforce_spares_dcr_by_optempo where MDS = :nsns
BulkPOLAirforceMDS=select MDS, FUEL_NSN, OPTEMPO, GALLONS_PER_DAY from airforce_fuels_dcr_by_optempo where MDS = :nsns
# Marine
# 
ConsumableMarineTAMCN=select TAMCN, PART_NSN, OPTEMPO, DCR from mcgrd_spares_dcr_by_optempo where TAMCN = :nsns
ConsumableMarineMDS=select MDS,NSN, OPTEMPO, DEMANDS_PER_DAY from usmcair_spares_dcr_byoptempo where MDS = :nsns
BulkPOLMarineTAMCN=select TAMCN, FUEL_NSN, OPTEMPO, GALLONS_PER_DAY from marine_ground_fuels_dcr_by_op where TAMCN = :nsns 
BulkPOLMarineMDS=select MDS, FUEL_NSN, OPTEMPO, GALLONS_PER_DAY from marine_air_fuels_dcr_by_op where MDS = :nsns
# Navy
#
ConsumableNavyMEI=select MEI_ID, NSN, OPTEMPO, DCR from navy_spares_dcr_by_optempo where MEI_ID = :nsns
ConsumableNavyMDS=select MDS, NSN, OPTEMPO, DEMANDS_PER_DAY from navyair_spares_dcr_by_optempo where MDS = :nsns
# Prototype & Property Provider
#
%com.bbn.alpicis.plugins.IcisPrototypeProvider
%com.bbn.alpicis.plugins.IcisPropertyProvider2

# Now, get the assets from jtav
%SQLAssetCreator
DB_NAME1 = jdbc:postgresql:${org.cougaar.database}
query1 = select NSN, QTY_OH, NOMENCLATURE from jtav_equipment \
where  UIC4 = substr(:uic, 1, 4) and \
  NSN in ('1055013296826', \
          '1055012519756', \
          '1055011920358', \
          '1055011920357', \
          '1055011920596', \
          '1520011069519', \
          '2320010970249', \
          '2320011231602', \
          '2320011289552', \
          '2350001226826', \
          '2350010871095', \
          '2350012197577', \
          '2350012487619', \
          '2350012487620', \
          '2350013050028', \
          '2350014059886', \
          '1055013296826', \
          '1520010350266', \
          '1520010820686', \
          '1520011069519', \
          '1520011255476', \
          '2320011007673', \
          '2320011077155', \
          '2320013042278', \
          '2320013189902', \
          '2330013035197', \
          '2330013038832', \
          '2350001226826', \
          '2350010853792', \
          '2350010871095', \
          '2350012197577', \
          '2350012487620', \
          '2350013050028', \
          '3990013077676')



