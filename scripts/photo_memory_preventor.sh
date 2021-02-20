#!/bin/bash

echo "About to kill all photo* processes..."
killall "Photos Agent"
killall photolibraryd
killall photoanalysisd
exit