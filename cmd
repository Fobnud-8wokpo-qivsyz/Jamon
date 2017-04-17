    _   ___________________ __  __
   / | / / ____/_  __/ ___// / / /
  /  |/ / __/   / /  \__ \/ /_/ / 
 / /|  / /___  / /  ___/ / __  /  
/_/ |_/_____/ /_/  /____/_/ /_/   
                                ______________________________________________NETSH
                                
#nesth firewall add portopening TCP 666 PuertaDelDiablo                →Abrimos puerto en el Firewall. 
#netsh firewall delete portopening TCP 666                             →Cerramos el puerto




___   __  _    _  ___  ___   ___  _  _  ___  __    __   
(  ,\ /  \( \/\/ )(  _)(  ,) / __)( )( )(  _)(  )  (  )  
 ) _/( () )\    /  ) _) )  \ \__ \ )__(  ) _) )(__  )(__ 
(_)   \__/  \/\/  (___)(_)\_)(___/(_)(_)(___)(____)(____)___________________POWERSHELL

>>Get-ExecutionPolicy        //ver el estado de 'Ejecucion de Scripts'
>>Set-ExecutionPolicy Unrestricted        //Set 'Ejecucion de Scripts to Unrestricted mode'





___ ___ ___ __  __ 
|   \_ _/ __|  \/  |
| |) | |\__ \ |\/| |
|___/___|___/_|  |_|
                    
                    _________________Habilitar o deshabilitar características de Windows con DISM
                    
Para montar una imagen sin conexión para mantenimiento:

Usa la opción /Get-ImageInfo para recuperar el nombre o el número de índice de la imagen que quieres modificar. 
La mayoría de las operaciones que especifican un archivo de imagen requieren un valor de índice o de nombre.
#Dism /Get-ImageInfo /ImageFile:C:\test\images\install.wim

Monta la imagen de Windows sin conexión. Por ejemplo, escribe:
#Dism /Mount-Image /ImageFile:C:\test\images\install.wim /Name:"Base Windows Image" /MountDir:C:\test\offline

#Dism /online /Get-Features                     →Listar todas las caracteristicas disponibles
#Dism /Image:C:\test\offline /Get-Features      →Para dar servicio a una imagen sin conexión,
                                                 especifica la ubicación del directorio de la imagen montada  

#Dism /Image:C:\test\offline /Get-Features      →Redirigir a un file.txt las caracteristicas disponibles

Habilita una característica específica en la imagen. 
Puedes usar el argumento /All para habilitar todas las características primarias en el mismo comando. Por ejemplo, escribe:
#Dism /online /Enable-Feature /FeatureName:TFTP /All

Para dar servicio a una imagen sin conexión, especifica la ubicación del directorio de la imagen montada
#Dism /Image:C:\test\offline /Enable-Feature /FeatureName:TFTP /All

#Dism /online /Get-FeatureInfo /FeatureName:TFTP       →obtén el estado de la característica que has habilitado
                                                        Si el estado es Habilitación pendiente, debes arrancar 
                                                        la imagen para poder habilitar la característica por completo.
                                                        
REF:https://msdn.microsoft.com/es-es/library/hh824822.aspx

