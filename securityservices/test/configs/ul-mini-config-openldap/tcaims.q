# Live TCAIMS query 
Driver=com.sybase.jdbc2.jdbc.SybDriver
Database = jdbc:sybase:Tds:${tcaims.database}
Username = ${tcaims.database.user}
Password = ${tcaims.database.password}

pacing = '2350010871095'

# get 'eaches' for all 'pacing' assets
%SQLNamedAssetCreator
query = select mis_nsn_id, bumper_nr+'_'+uei_serial_nr, uei_desc_tx \
  from b_unit_equipment_item \
  where unit_id = :uic and ti_id is not null \
  and mis_nsn_id = :pacing 


%SQLAggregateAssetCreator
query = select mis_nsn_id, count(*), uei_desc_tx from b_unit_equipment_item \
where  unit_id = :uic and ti_id is not null \
  and mis_nsn_id not in (:pacing) and \
  mis_nsn_id in ('1025010266648', \
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
	group by mis_nsn_id, uei_desc_tx

