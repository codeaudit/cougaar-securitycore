# gdss query

%SQLNamedAssetCreator
Database = jdbc:postgresql:${tops.database}
Username = ${org.cougaar.database.user}
Password = ${org.cougaar.database.password}
query = select ac_type, tail_fleet, ac_type \
  from gdss_aircraft \
  where home_icao = :icao \
  and ac_type in (:actypes)

