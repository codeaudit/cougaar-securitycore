%Global
Driver=org.postgresql.Driver
Database=jdbc:postgresql:${org.cougaar.database}
Username = ${org.cougaar.database.user}
Password = ${org.cougaar.database.password}

# First, get the PERSONNEL and generate an aggregate asset
%SQLAggregateAssetCreator
query = select 'Personnel' AS NSN, PERSONNEL AS QTY_OH, 'MilitaryPersonnel' AS NOMENCLATURE \
	from ue_summary_mtmc \
    	where UIC = :uic

# Then, get the containers and generate an aggregate asset
%SQLAggregateAssetCreator
query = select '8115001682275' AS NSN, container_20_ft_qty AS QTY_OH, 'Container' AS NOMENCLATURE \
	from ue_summary_mtmc \
	where UIC = :uic


# Now, get the assets from jtav
%SQLAssetCreator
query = select NSN, QTY_OH, NOMENCLATURE from jtav_equipment \
where  UIC4 = substr(:uic, 1, 4) and \
  NSN in (
          '1055011920357', \ -- L44894: M270 Multiple Launch Rocket System      (NSN Not in JTAV)
          '1055011920358', \ -- L44894: M270 Multiple Launch Rocket System      (NSN Not in JTAV)
          '1055011920596', \ -- L44894: M270 Multiple Launch Rocket System      (NSN Not in JTAV)
          '1055012519756', \ -- L44894: M270 Multiple Launch Rocket System      (NSN Not in JTAV)
          '1055013296826', \ -- L44894: M270 Multiple Launch Rocket System      (NSN in JTAV)
          '1055013296826', \ -- Duplicate
          '1520010350266', \ -- K32293: Helicopter: UH-60A              (NSN in JTAV)
          '1520010820686', \ -- H30616: Helicopter: EH-60A              (NSN in JTAV)
          '1520011069519', \ -- H28647: Helicopter: AH-64A              (NSN in JTAV)
          '1520011069519', \ -- Duplicate
          '1520011255476', \ -- A21633: Helicopter: OH-58D              (NSN in JTAV)
          '2320010970249', \ -- T58161: M978 WWN HEMTT Truck Tank Fuel 8x8      (NSN in JTAV)
          '2320011007672', \ -- T87243: HEMMT: M978 WOWN (Tank)         (NSN in JTAV) (Added)
          '2320011007673', \ -- T39586: HMMWV: M985                     (NSN in JTAV)
          '2320011077155', \ -- T61494: HMMWV: M998                     (NSN in JTAV)
          '2320011231602', \ -- E0947:  Light Armored Vehicle                   (NSN Not in JTAV, Marine Equipment) 
          '2320011289552', \ -- T92310: M1026 HMMWV Truck Utility 1-1/4 Ton     (NSN in JTAV)
          '2320013042278', \ -- T40999: PLS Truck: M1075                (NSN in JTAV)
          '2320013189902', \ -- T59048: HET Tractor: M1070              (NSN in JTAV)
          '2330013035197', \ -- T93761: PLS Trailer: M1076              (NSN in JTAV)
          '2330013038832', \ -- S70859: HET Trailer: M1000              (NSN in JTAV)
          '2350001226826', \ -- R50681: Recovery Vehicle: M88A1         (NSN in JTAV)
          '2350001226826', \ -- Duplicate
          '2350010853792', \ -- C12155: TrackedPersonnelCarrier: M981   (NSN in JTAV)
          '2350010871095', \ -- T13168: Tank: M1A1                      (NSN in JTAV)
          '2350010871095', \ -- Duplicate
          '2350012197577', \ -- C18234: PersonnelCarrier: M113A3        (NSN in JTAV)
          '2350012197577', \ -- Duplicate
          '2350012487619', \ -- F40375: M2A2 Fighting Vehicle HS                (NSN Not in JTAV)
          '2350012487620', \ -- F60530: M3A2 Fighting Vehicle HS                (NSN in JTAV, Wrong LIN)
          '2350012487620', \ -- Duplicate
          '2350013050028', \ -- H57642: Howitzer: M109A6                (NSN in JTAV)
          '2350013050028', \ -- Duplicate
          '2350014059886', \ -- F40375: Fighting Veh: M2A2 W/ODS        (NSN in JTAV)
          '3990013077676'  \ -- B83002: PLS Flatrack: M1077             (NSN in JTAV)
)
