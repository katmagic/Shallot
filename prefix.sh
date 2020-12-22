#!/bin/bash
NAME=$1
FILE=`mktemp`
counter=$2

while [ $counter -gt 0 ]
do
  if ./shallot -f $FILE "^$NAME"
  then
    URL=`grep "$NAME[a-z0-9]*\.onion$" $FILE | cut -d' ' -f7`

    echo "`date` - $URL for $NAME"
    mkdir -p "./$URL"
    grep BEGIN -A 20 $FILE > $URL/private_key
    chmod -R 400 ./$URL/private_key
    chmod -R 700 ./$URL/

    cat $FILE
    rm -f $FILE
  else
    echo $counter:$? ERROR
  fi

  ((counter--))
done
