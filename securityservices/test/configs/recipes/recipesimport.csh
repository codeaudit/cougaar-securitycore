#!/bin/tcsh

set db=csmart1020
mysql -f -u root -pultralog ${db} < recipeQueriesAll.sql

