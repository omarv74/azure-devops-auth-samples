$flowTriggerURI = 'https://prod-03.westcentralus.logic.azure.com:443/workflows/834bd3d6d9f942f69222b7951ff2fc66/triggers/manual/paths/invoke?api-version=2016-06-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=Ni_-QhC-3c8LhixJo4GCdOXn3kB4RSBrtF-_pBrEM0Q'
$messageSubject = 'Testing Trigger'
$messageBody='Executing trigger from PowerShell'
$params = @{"messageSubject"="$messageSubject";"messageBody"="$messageBody"}
Invoke-WebRequest -Uri $flowTriggerURI -Method POST -ContentType "application/json" -Body ($params|ConvertTo-Json)