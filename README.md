# Peek2Report

## Please clone with -- recursive option
```
git clone https://github.com/cmelakmartin/Peek2Report.git --recursive
```
## Install pip requirements
```
cd Peek2Report
pip install -r requirements.txt 
```
## Update paths
Please update paths for input and output folder and add path of emit.log

## Check and prepare input files
Please check whether input CSV files have one machine per line and they are not clustered (e.g. host[01-20] have IP 192.168.0.[1-20]).
Also, check if Emit.log has all techniques in correct format (e.g. T1031: Scheduled task)

## Report creation
Once the script is finished, it will create output files for ATT&CK Navigator (JSON), RawGraphs tool in CSV (https://app.rawgraphs.io/) and Report.MD
Matrix in Navigator shall be copied and added to Report.MD as well as graphs and diagrams from RawGraphs. Also, it is reccomend to title them. 

Report can be previewed on GitHub or locally using grip (https://github.com/joeyespo/grip). Report can be converted to PDF while it is a good practice to use ```<div class="pagebreak"> </div>``` in inspect element mode. 



