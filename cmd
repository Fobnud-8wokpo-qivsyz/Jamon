___________________WMI and PYTHON____________________________________________________________________________________
#python -m pip install wmi
#python -m pip install pywin32  //En caso de que tengamos el error: "no module named Win32com"

-En el Interprete de Python:

import wmi
conn = wmi.WMI("192.168.1.1", user="usuario", password="contraseña") //Conexión Remota
conn = wmi.WMI()                                                     //Conexión Local

>>>for class_name in conn.classes:              //Estas lineas devolveran una lista de WMI Classes       
...    if 'Process' in class_name:
...        print(class_name)       

>>>wmi.WMI().Win32_Process.methods.keys()      //Esta linea detallaran los metodos de la clase Win32_Process
>>>wmi.WMI().Win32_Process.properties.keys()   //Esta linea detallaran las propiedades de la clase Win32_Process

>>>import wmi                                  //Estas lineas retornaran una lista de los objetos de la clase Win32_Process
>>>conn = wmi.WMI()
>>>for process in conn.Win32_Process():
        print("ID: {0}\nHandleCount: {1}\nProcessName: {2}\n".format(process.ProcessId, process.HandleCount, process.Name))


>>>import wmi
>>>conn = wmi.WMI()
>>>pid, returnval= conn.Win32_Process.Create(CommandLine="notepad.exe")  //Inicia un proceso y captura su PID
>>>conn.Win32_Process(ProcessId=pid)[0].Terminate()                      //Extermina el proceso del PID capturado


>>>import wmi
>>>conn = wmi.WMI()
>>>for s in conn.Win32_Service(StartMode="Auto", State="Stopped"):      //Detecta procesos Detenidos
...      if 'Update' in s.Name:                                         
...              result, = s.StartService()                             //Usamos el método StartService P/iniciar los procesos         
...      if result == 0:                                                //Podemos usar StopService P/detener procesos        
...              print("Successfully started service:", s.Name)


>>>import wmi
>>>conn = wmi.WMI()                                                     //Detectar Espacio libre en discos
>>>for disk in conn.Win32_LogicalDisk():
...      if disk.size != None:
...             print(disk.Caption, "is {0:.2f}% free".format(100*float(disk.FreeSpace)/float(disk.Size)))


>>>import wmi
>>>conn = wmi.WMI()
>>>for group in conn.Win32_Group():                                     //Obtener Usuarios y Grupos Locales
...     print(group.Caption)
...     for user in group.associators(wmi_result_class="Win32_UserAccount"):
...             print(" [+]", user.Caption)




___________________NETSH_____________________________________________________________________________________________
                                
#nesth firewall add portopening TCP 666 PuertaDelDiablo                →Abrimos puerto en el Firewall. 
#netsh firewall delete portopening TCP 666                             →Cerramos el puerto



___________________POWERSHELL________________________________________________________________________________________

>>Get-ExecutionPolicy        //ver el estado de 'Ejecucion de Scripts'
>>Set-ExecutionPolicy Unrestricted        //Set 'Ejecucion de Scripts to Unrestricted mode'



___________________DISM Habilitar o deshabilitar características de Windows con DISM_________________________________
                    
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

