Database=jdbc:postgresql:${org.cougaar.database}
Driver = org.postgresql.Driver
Username = ${blackjack.database.user}
Password = ${blackjack.database.password}
MIN_IN_POOL= 1
MAX_IN_POOL= 4
TIMEOUT= 1
NUMBER_OF_TRIES= 2

# PATIENT CONDITIONS
#
#conditionQuery = select NOMENCLATURE from patient_conditions where PATIENTCONDITION = :pc
conditionQuery = select PC_TITLE from patient_condition where PC = :pc

# All Services (for now)
#ClassVIIIMedical=select NSN, DCR from medical_dcr where PATIENTCONDITION = :pc AND LEVELOFCARE = :loc order by DCR 
#ClassVIIIMedical = select MATERIEL, QUANTITY_MATERIEL_USED from ttt_treatments where PC = :pc AND LEVEL_OF_CARE = :loc AND (MATERIEL LIKE '6505%' OR MATERIEL LIKE '6510%' OR MATERIEL LIKE '6515%')
#ClassVIIIMedical = select ttt_treatments.MATERIEL, ttt_treatments.QUANTITY_MATERIEL_USED, CSG_MASTER.NSN, CSG_MASTER.QUANTITY_USED FROM ttt_treatments, CSG_MASTER WHERE ttt_treatments.MATERIEL = CSG_MASTER.CSG (+) AND ttt_treatments.PC = :pc AND ttt_treatments.LEVEL_OF_CARE = :loc AND (CSG_MASTER.NSN LIKE '6505%' OR CSG_MASTER.NSN LIKE '6510%' OR CSG_MASTER.NSN LIKE '6515%' OR ttt_treatments.MATERIEL LIKE '6505%' OR ttt_treatments.MATERIEL LIKE '6510%' OR ttt_treatments.MATERIEL LIKE '6515%')
ClassVIIIMedical = select ttt_treatments.MATERIEL, ttt_treatments.QUANTITY_MATERIEL_USED, CSG_MASTER.NSN, CSG_MASTER.QUANTITY_USED, TRAY_MASTER.NSN, TRAY_MASTER.TRAY_QUANTITY, ttt_treatments.PERC_PATIENTS_TREATED FROM ttt_treatments, CSG_MASTER, TRAY_MASTER WHERE ttt_treatments.MATERIEL = CSG_MASTER.CSG (+) AND ttt_treatments.MATERIEL = TRAY_MASTER.TRAY (+) AND ttt_treatments.PC = :pc AND ttt_treatments.LEVEL_OF_CARE = :loc AND (TRAY_MASTER.NSN LIKE '6505%' OR TRAY_MASTER.NSN LIKE '6510%' OR TRAY_MASTER.NSN LIKE '6515%' OR CSG_MASTER.NSN LIKE '6505%' OR CSG_MASTER.NSN LIKE '6510%' OR CSG_MASTER.NSN LIKE '6515%' OR ttt_treatments.MATERIEL LIKE '6505%' OR ttt_treatments.MATERIEL LIKE '6510%' OR ttt_treatments.MATERIEL LIKE '6515%')
