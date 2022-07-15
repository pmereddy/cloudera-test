#!/bin/bash
set -ieu

CM_WEB_URL="https://ccycloud-1.pramodh-cdhu-634.root.hwx.site:7183/api/v33"
CM_USERNAME="admin"
CM_PASSWORD="admin"

AUTH_HEADER=$(echo -n "$CM_USERNAME:$CM_PASSWORD" | base64)

CM_RESOURCES=(
"cm/allHosts/config?view=FULL"
"audits"
"authRoleMetadatas"
"authRoles"
"authRoles/metadata"
"cm/authService"
"cm/authService/config"
"cm/authService/roleTypes"
"cm/authService/roleConfigGroups"
"cm/authService/roles"
"cm/service"
"cm/service/config"
"cm/service/roleConfigGroups"
"cm/service/roles"
"cm/service/roleTypes"
"cm/config"
"cm/deployment"
"cm/kerberosInfo"
"cm/kerberosPrincipals"
"cm/license"
"cm/licensedFeatureUsage"
"cm/scmDbInfo"
"cm/shutdownReadiness"
"cm/version"
"cm/peers"
"datacontexts"
"externalAccounts/supportedCategories"
"externalUserMappings"
"clusters?clusterType=ANY&view=FULL"
"hosts?view=FULL"
"users?view=FULL"
)

CLUSTER_RESOURCES=(
"clusters/{clusterName}?clusterType=base&view=FULL"
"clusters/{clusterName}/clientConfig"
"clusters/{clusterName}/dfsServices"
"clusters/{clusterName}/export"
"clusters/{clusterName}/hosts"
"clusters/{clusterName}/hostTemplates"
"clusters/{clusterName}/kerberosInfo"
"clusters/{clusterName}/serviceTypes"
"clusters/{clusterName}/utilization"
"clusters/{clusterName}/services"
"clusters/{clusterName}/parcels"
"clusters/{clusterName}/parcels/usage"
)

HOST_RESOURCES=(
"hosts/{hostId}"
"hosts/{hostId}/config"
)

rawurlencode() {
  local string="${1}"
  local strlen=${#string}
  local encoded=""
  local pos c o

  for (( pos=0 ; pos<strlen ; pos++ )); do
     c=${string:$pos:1}
     case "$c" in
        [-_.~a-zA-Z0-9] ) o="${c}" ;;
        * )               printf -v o '%%%02x' "'$c"
     esac
     encoded+="${o}"
  done
  echo "${encoded}"    # You can either set a return variable (FASTER)
}


BASE_DIR="results_$(date +%s)"
mkdir -p $BASE_DIR
echo "Storing Cloudera cluster information in $BASE_DIR ..."
for res in "${CM_RESOURCES[@]}"
do
    SUB_FOLDER=$(echo $res | awk -F'?' '{print $1}')
    mkdir -p $BASE_DIR/$SUB_FOLDER
    curl --silent --insecure -X GET $CM_WEB_URL/$res -H "accept: application/json" -H "authorization: Basic $AUTH_HEADER" -o $BASE_DIR/$SUB_FOLDER/results.json
done

cat $BASE_DIR/clusters/results.json  | grep -w "name" | awk -F':' '{print $2}' |grep -o "\".*\"" | sed 's/"//g' > /tmp/cldr_clusters

while read cluster; do
  cluster=$(rawurlencode "$cluster")
  for res in "${CLUSTER_RESOURCES[@]}"; do
    res=$(echo $res |sed "s/{clusterName}/$cluster/g")
    SUB_FOLDER=$(echo $res | awk -F'?' '{print $1}')
    mkdir -p $BASE_DIR/$SUB_FOLDER
    curl --silent --insecure -X GET $CM_WEB_URL/$res -H "accept: application/json" -H "authorization: Basic $AUTH_HEADER" -o $BASE_DIR/$SUB_FOLDER/results.json
  done
done < /tmp/cldr_clusters


cat $BASE_DIR/hosts/results.json  | grep -w "hostId" | awk -F':' '{print $2}' |grep -o "\".*\"" | sed 's/"//g' > /tmp/cldr_cluster_hosts

while read host; do
  host=$(rawurlencode "$host")
  for res in "${HOST_RESOURCES[@]}"; do
    res=$(echo $res |sed "s/{hostId}/$host/g")
    SUB_FOLDER=$(echo $res | awk -F'?' '{print $1}')
    mkdir -p $BASE_DIR/$SUB_FOLDER
    curl --silent --insecure -X GET $CM_WEB_URL/$res -H "accept: application/json" -H "authorization: Basic $AUTH_HEADER" -o $BASE_DIR/$SUB_FOLDER/results.json
  done
done < /tmp/cldr_cluster_hosts
