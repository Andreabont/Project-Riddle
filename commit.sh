#!/bin/bash
git add .
data_corrente = `date +%d/%m/%Y\ %H:%M`
git commit -m 'Update $data_corrente'
git push -u origin master

