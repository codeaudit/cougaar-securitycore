Database=jdbc:postgresql:${org.cougaar.database}
Driver = org.postgresql.Driver
Username = ${blackjack.database.user}
Password = ${blackjack.database.password}
MIN_IN_POOL= 1
MAX_IN_POOL= 4
TIMEOUT= 1
NUMBER_OF_TRIES= 2

# PATIENT CONDITION DISTRIBUTION QUERY
#
pcQuery = select patient_condition.PC, PC_TITLE, PATIENT_CLUSTER from patient_condition, patient_clusters where TO_NUMBER(patient_condition.PC)=TO_NUMBER(PATIENT_CLUSTERS.PC(+)) order by patient_condition.PC
#distributionQuery = select PC,WIA,NBI,DISEASE from sw_asia_pc_distribution order by PC
#distributionQuery = select PC,WIA,NBI,DISEASE from patient_distributionS where NAME='PATGEN Default for SW_ASIA region' order by PC
#distributionQuery = select PC,WIA,NBI,DISEASE from patient_distributionS where NAME='PC148 Only' order by PC
distributionQuery = select PC,WIA,NBI,DISEASE from patient_distributionS where NAME='Minimal Distribution' order by PC
