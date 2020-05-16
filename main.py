import json
import pandas as pd
from pandas.io.json import json_normalize  
import csv
import sys
import os
import glob
import time
import unicodedata
from stix2 import FileSystemSource,Filter

#INTPUTS
ATOMIC = 'atomic-red-team/' #atomic red team library
CTI = '/cti/enterprise-attack' #cti library

SYSTEMS = 'systems/' #folder containing CSV
EMIT = 'input/emit.jsonl' #logfile emitted by peek

OUTPUT = 'output/' #output directory

#-------------------------------------------------------------
startTime = time.time() #time measurement
fs = FileSystemSource(CTI)
filt = Filter('type', '=', 'attack-pattern')

#CTI API
def get_object_by_attack_id(src, typ, attack_id):
    filt = [
        Filter('type', '=', typ),
        Filter('external_references.external_id', '=', attack_id)
    ]
    return src.query(filt)

def get_mitigations_by_technique(src, tech_stix_id):
    relations = src.relationships(tech_stix_id, 'mitigates', target_only=True)
    return src.query([
        Filter('type', '=', 'course-of-action'),
        Filter('id', 'in', [r.source_ref for r in relations])
    ])

def get_mitigation_by_object(objectID):
        try:
            tech = get_object_by_attack_id(fs, 'attack-pattern', objectID)[0]
            mitig = get_mitigations_by_technique(fs, tech.id)[0]
            return mitig.name
        except:
            return "Not Defined"

def get_technique_by_name(src, name):
    filt = [
        Filter('type', '=', 'attack-pattern'),
        Filter('name', '=', name)
    ]
    return src.query(filt)

#some techniques are wrongly named in EMIT.log
def technique_correlation(technique):
    if technique == "1053: Scheduled Task":
        technique = "T1053: Scheduled Task"
    if technique == "t1053: Scheduled Task":
        technique = "T1053: Scheduled Task"
    if technique == "1218: Office Signed Binary Proxy Execution":
        technique == "T1218: Office Signed Binary Proxy Execution"
    return technique
#-------------------------------------------------------------
#create report in MarkDown format
def create_md(techniques,counts):
    toAppend = '' 
    outputFile = open(OUTPUT+"report.md", "a")
    csvRow = [['GameMeta_MitreAttack_ID','Count','Mitigation','Data Source']]
    csvOut = open(OUTPUT +'mitig.csv', 'w')
    
    #create Menu
    outputFile.write("# **Used techniques sorted by descending occurrance** \n***\n")

    for technique in techniques: 
        
        technique = technique_correlation(technique)
                 
        if technique != ":" or technique != ""  or str(technique) != "nan" :        
            print(technique)    
            outputFile.write("- ["+technique+"](#"+technique.replace(' ','-').replace(':','').lower().strip()+")\n")
    
    print("Techniques were loaded in: "+"--- %s seconds ---" % (time.time() - startTime))
    ctiStartTime = time.time()

    
    for technique in techniques:
        
        technique = technique_correlation(technique)
        
        if  technique != ":" or technique != "" or technique != "T":     
            techID = str(technique.split(':')[0].strip())
            print(techID)

            outputFile.write("# **"+technique+"** \n***\n")

        #Atomic test presence
            try:
                mdFile = open(ATOMIC+"atomics/"+techID+"/"+techID+".md","r")
                next(mdFile)
                for line in mdFile:
                    outputFile.write(line)

            except: 
                toAppend += '## **Atomic tests for '+techID+'**\n Atomic test not present. \n***\n'

        #data sources
            try:
                dataSrsc = get_technique_by_name(fs, technique.split(':')[1].strip())[0].x_mitre_data_sources#[0]
                detection = get_technique_by_name(fs, technique.split(':')[1].strip())[0].x_mitre_detection
            # Mitigations Presence
                tech = get_object_by_attack_id(fs, 'attack-pattern', techID)[0]
                mitig = get_mitigations_by_technique(fs, tech.id)

                toAppend += '\n## ***Mitigations for '+techID+':*** \n'

                if len(mitig):
                    for m in mitig:
                        toAppend += '### '+m.name+'\n'+m.description+'\n'
                        if len(dataSrsc):
                           [csvRow.append([techID+': '+tech.name,counts[technique],m.name,d])for d in dataSrsc]                      
                        else:
                            csvRow.append([techID+': '+tech.name,counts[technique],m.name])


                        if len(m.external_references):
                            toAppend += '#### References \n'
                        for ref in m.external_references:
                            toAppend+='* '+ ref.source_name+'::'
                            if hasattr(ref, 'description'): #object has attribute desc
                                toAppend+=ref.description +'\n\n'
                            if hasattr(ref, 'url'): #object has attribute desc
                                toAppend+=' ['+ref.url +']('+ref.url +')\n\n'

                else:
                    toAppend += 'No mitigations specified yet\n\n'


                toAppend += '\n## ***Detection of '+techID+':*** \n'
                toAppend += detection+'\n'

                toAppend += '\n## ***Data Sources for detection of '+techID+':*** \n'
                if len(dataSrsc):
                    for d in  dataSrsc:
                        toAppend+=d+'\n\n'
                else:
                     toAppend += 'No datasources specified yet\n\n'
            except:
                toAppend += 'There was a problem while attempting to obtain mitigations/datasources\n\n'
                print("mitigation/dtasrc problem")
                
            outputFile.write(toAppend.encode("utf-8"))
            mitig=[]
            tech=[]
            toAppend = ''
        
    outputFile.close()
    with csvOut:
        writer = csv.writer(csvOut)
        writer.writerows(csvRow)
    print("script finished in: "+"--- %s seconds ---" % (time.time() - ctiStartTime))
    print("script finished in: "+"--- %s seconds ---" % (time.time() - startTime))

#functions for work with JSONl format 
def dump_jsonl(data, output_path, append=False):
     
    mode = 'a+' if append else 'w'
    with open(output_path, mode,) as f:
        for line in data:
            json_record = json.dumps(line, ensure_ascii=False)
            f.write(json_record + '\n')
    print('Wrote {} records to {}'.format(len(data), output_path))

def load_jsonl(input_path):
    data = []
    with open(input_path, 'r') as f:
        for line in f:
            data.append(json.loads(line.rstrip('\n|\r')))
            
    print('Loaded {} records from {}'.format(len(data), input_path))
    return data

#-------------------------------------------------------------
#LOAD CSVs
domains=[]
all_files = glob.glob(SYSTEMS + "/*.csv")
li = []

for filename in all_files:
    dfFile = pd.read_csv(filename, sep=";", index_col=False, header=0)
    dfFile['Domain'] = os.path.splitext(filename)[0].split("/")[-1]
    domains.append(os.path.splitext(filename)[0].split("/")[-1])
    li.append(dfFile)
    
uData = pd.concat(li, axis=0, ignore_index=False) #merging all data into one dataframe
uData.rename(columns = {'Page name':'GameMeta_Host', 'IP':'source_ip'}, inplace = True) # set the same indexes for correlation between CSV and JSONL
uData
uData['destination_ip']=uData['source_ip'] # creation of destination_ip column, value equals local ip by default

uDataShort = uData[['GameMeta_Host','Domain','source_ip','destination_ip']] #shorten dataframe of all machines from CSV

#load EMIT file
data = load_jsonl(EMIT)
db_data = json_normalize(data)
db_cols = ['GameMeta.Host','GameMeta.MitreAttack.ID','GameMeta.MitreAttack.Name', '@timestamp', 'message',  'destination.ip', 'source.ip']
        
df = pd.DataFrame(db_data, columns=db_cols)
df.rename(columns = {'GameMeta.Host':'GameMeta_Host','GameMeta.MitreAttack.ID':'GameMeta_MitreAttack_ID','GameMeta.MitreAttack.Name':'GameMeta_MitreAttack_Name' ,'@timestamp':'timestamp','destination.ip':'destination_ip', 'source.ip':'source_ip'}, inplace = True) # set the same indexes for correlation between CSV and JSONL


df.dropna(subset = ["GameMeta_MitreAttack_Name"], inplace=True)
#filling missing IP adresses in EMIT from SYSTEMS csv (mostly from linux sources)
merged_left = pd.merge(left=df, right=uDataShort, how='left', left_on='GameMeta_Host', right_on='GameMeta_Host')

merged_left['source_ip_x'].fillna(merged_left['source_ip_y'],inplace=True)
merged_left['destination_ip_x'].fillna(merged_left['destination_ip_y'],inplace=True)

#add coulumn 'count' summarising the usage of techniques 
merged_left['count'] = merged_left.groupby('GameMeta_MitreAttack_ID')['GameMeta_MitreAttack_ID'].transform('count')

#cycle for creation output files according to the domain
for dom in domains:
    #CSV output for timeline graph 
    csvRow = [['GameMeta_MitreAttack_ID','timestamp']]
    csvOut = open(OUTPUT +'timeline_'+dom+'.csv', 'w')
    
    #ATT&CK Navigator layer declaration
    layer_json = {
            "version": "2.2",
            "name": dom,
            "description": "Layer for domain"+dom,
            "domain": "enterprise",
            "techniques": []
        }
    #DataFrame of unique techniques used in domain
    domainDf=merged_left.loc[merged_left['Domain'] == dom]    
    unique=domainDf.drop_duplicates(subset=['GameMeta_MitreAttack_ID'])    
    
    #Number of total events (triggered techniques) of current domain  
    total = float(unique['count'].sum())
    
    #ATT&CK Navigator layer content - techniques
    for index,row in unique.iterrows():
        if row['GameMeta_MitreAttack_ID'] == "1053":
            row['GameMeta_MitreAttack_ID'] = "T1053"
            
        technique = {
            "techniqueID": row['GameMeta_MitreAttack_ID'],
            "score": (float(row['count'])/total)*100
        }

        layer_json["techniques"].append(technique)
    
    with open(OUTPUT+""+dom+'.json', 'w') as outfile:
        json.dump(layer_json, outfile, indent=4)
        
    #Fill content of CSV file for timeline graph
    for index, row in domainDf.iterrows():        
        csvRow.append([row.GameMeta_MitreAttack_Name,row.timestamp])
    
    with csvOut:
        writer = csv.writer(csvOut)
        writer.writerows(csvRow)
        
  

    
merged_left = merged_left.loc[merged_left['Domain'] == "INT"]   
unique=merged_left.drop_duplicates(subset=['GameMeta_MitreAttack_ID'])


#Create md report
create_md(unique['GameMeta_MitreAttack_Name'].tolist(),dict(zip(unique['GameMeta_MitreAttack_Name'], unique['count'])))#get count of used techniques and append mitigations






