#!/usr/bin/bash

urlscan_1_import="urlscan-py-1-input.db"
urlscan_2_ready="urlscan-py-2-ready.db"
urlscan_3_done="urlscan-py-3-done.db"

for x in `head -1 $urlscan_2_ready`
do
    sudo docker run --rm -i heywoodlh/urlscan-py scan -p --api "API_TOKEN" --url http://$x
    sudo docker run --rm -i heywoodlh/urlscan-py scan -p --api "API_TOKEN" --url https://$x
    echo https://$x
    echo $x | tee -a $urlscan_3_done
    sed -e '1d' $urlscan_2_ready > tmp.txt
    mv tmp.txt $urlscan_2_ready
done
