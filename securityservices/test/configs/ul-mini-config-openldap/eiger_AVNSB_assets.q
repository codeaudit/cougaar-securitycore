Driver = org.postgresql.Driver
Database = jdbc:postgresql:${org.cougaar.database}
Username = ${org.cougaar.database.user}
Password = ${org.cougaar.database.password} 

pacing =  '2320010970249', '2320011007672', '2320011077155'

# First, get the PERSONNEL and generate an aggregate asset
# %SQLAggregateAssetCreator
# query = select 'Personnel' AS NSN, PERSONNEL AS QTY_OH, 'MilitaryPersonnel' AS NOMENCLATURE \
# 	from ue_summary_mtmc \
#     	where UIC = :uic

# Next, get the MOS levels and generate an aggregate asset
%SQLAggregateAssetCreator
query = select CAPABILITY AS MOS_LEVEL, PERSONNEL AS MOS_QTY, 'Dummy Nomenclature' AS DUMMYNOMENCLATURE \
	from org_mos \
	where UIC = :uic

# Then, get the containers and generate an aggregate asset
%SQLAggregateAssetCreator
query = select '8115001682275' AS NSN, container_20_ft_qty AS QTY_OH, 'Container' AS NOMENCLATURE \
	from ue_summary_mtmc \
	where UIC = :uic


# Now, get 'eaches' for all 'pacing' assets from JTAV
%SQLAssetCreator
query = select NSN, SUM(QTY_OH) AS "SUM(QTY_OH)", NOMENCLATURE from jtav_equipment \
where  UIC4 = substr(:uic, 1, 4) and \
  NSN in (:pacing) \
  group by NSN, NOMENCLATURE

# Now, get all 'non-pacing' assets as aggregates from JTAV
%SQLAggregateAssetCreator
query = select NSN, SUM(QTY_OH) AS "SUM(QTY_OH)", NOMENCLATURE from jtav_equipment \
where  UIC4 = substr(:uic, 1, 4) and \
  NSN not in (:pacing) and \
  NSN in ('1025010266648', \
          '1055011920357', \
          '1055011920358', \
          '1055011920596', \
          '1055012519756', \
          '1055013296826', \
          '1520010350266', \
          '1520010820686', \
          '1520011069519', \
          '1520011255476', \
          '2320010970249', \
          '2320011007672', \
          '2320011007673', \
          '2320011077155', \
          '2320011077156', \
          '2320011231602', \
          '2320011231606', \
          '2320011231607', \
          '2320011231608', \
          '2320011231609', \
          '2320011231612', \
          '2320011289552', \
          '2320011467189', \
          '2320011467190', \
          '2320013042278', \
          '2320013189902', \
          '2320013334129', \
          '2330013035197', \
          '2330013038832', \
          '2350001226826', \
          '2350010684089', \
          '2350010809087', \
          '2350010809088', \
          '2350010818138', \
          '2350010853792', \
          '2350010871095', \
          '2350012197577', \
          '2350012487619', \
          '2350012487620', \
          '2350013050028', \
          '2350014059886', \
          '3990013077676') \
	group by NSN, NOMENCLATURE
