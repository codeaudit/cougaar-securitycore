#!/bin/tcsh 
rm -f recipeQueriesAll.sql

ls *.sql > recipelist

foreach i ( `cat recipelist` )
  echo "cat" $i
  cat $i >> recipeQueriesAll.sql
end

