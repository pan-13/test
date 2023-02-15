<#
Funktion: Tool durchforstet die Verzeichnisse nach Dateien, scannt diese auf Viren und verschiebt sie dann in ein Freigabeverzeichnis
Entwickler: Stefan Reischl, Thomas Zimmermann. 
Changelog:
01.03.2019 - Version fertig gestellt
04.03.2019 - neue Anforderung: Scan durch mehrere Agents um Wartezeiten durch größere Scans zu vermeiden. Einbau eines Vorgang-Ordners im Temp-Verzeichnisses
06.03.2019 - Textdatei wird im Freigabe-Ordner erstellt, wenn Psydonymisieren nicht erfolgreich läuft
08.03.2019 - Textdatei wird im Freigabe-Ordner erstellt, wenn Entpacken nicht erfolgreich läuft 
12.03.2019 - ein defektes Archiv (Entpackungsfehler) wird nach D:\Datensicherung_Defekt verschoben
29.03.2019 - Punkt 6. If notmatch eingebaut um zu prüfen ob es sich wirklich nicht um eine Datensicherung handel. (gelöscht wurde if -match "systemcheck.azi") - von TZ
14.05.2019 - Die Variable Finish_Path wird nicht mehr unter Punkt 8 definiert, sondern nach der Psysonymisierung unter Punkt 9.
14.05.2019 - Wartungsdatei wird geprüft. Solange diese existiert bleibt der Dienst in einer Leerschleife. 
17.05.2019 - Control-Loging hinzugefügt. 
13.07.2021 - RKI-Format hinzugefügt.
#ToDo
#>
function Test-FileLock([string]$filePath)
{
	Rename-Item $filePath $filePath -ErrorVariable errs -ErrorAction SilentlyContinue
	return ($errs.Count -ne 0)
}
#Email
$emailSmtpServer = "mail.agenda.de"
$emailFrom = "Virenschutz <virenschutz@agenda-software.de>"
$emaildomain = "@agenda-software.de"
#Tools
$dasiunpack = "C:\Tools\DASIUnpack.exe"
$virenscanner1 = "C:\Emsisoft\a2cmd.exe"
$kdnr_tool = "C:\Tools\DasiKdNr.exe"
$psydo_tool = "C:\Tools\DASIPseudomize-Verzeichnis\DASIPseudomize.exe"
#Pfade
$path = "d:\Virenschutz\auf Viren scannen\*\*\*\*"
$quarantäne = "D:\Quarantäne"
$path_log = "D:\logs"
$psydo_tool_path = "C:\Tools\DASIPseudomize-Verzeichnis"
#Counter
$scanner = 1
$anzahl = 100000
While ($true)
{
	#Wartungsdatei prüfen. Solange die Datei existiert macht der Dienst nichts. 
	While (Test-path "C:\Tools\Service\Lock1.txt")
	{	
		write-host "Loop"
		Start-Sleep -Seconds 60	
	}
	$month = Get-Date -Format MM
	$year = (Get-Date).Year
	$datum_kurz = Get-Date -Format "yyyy-MM-dd"
	$fehler = @()
	$files = Get-ChildItem $path -Recurse | where { !$_.PsIsContainer }
	$path_csv = "d:\logs\$year-$month.csv"
	#Virenscanner aktualisieren
	#Start-Process -FilePath $virenscanner1 -ArgumentList "/u" -Wait -PassThru
	#Durchsuche die Ordner nach Dateien
	ForEach ($file in $files)
	{	
		#Wenn eine Datei gefunden wurde
		if (Test-Path $path)
		{		
			#wird die Datei aktuell verwendet?
			$verwendet = Test-FileLock $file	
			#falls ja dann mach mit der Schleife weiter
			If ($verwendet -eq "True")
			{ continue }		
			#falls nein beginne mit der eigentlichen Arbeit
			Else
			{				
				#Deklarationen der Basis-Variablen
				[string]$split = $file
				$datum = get-date
				$file_split = $split.Split("\")
				$file_split_0 = $file_split[0]
				$file_split_1 = $file_split[1]
				$file_split_2 = $file_split[2]
				$bereich = $file_split[3]
				$abteilung = $file_split[4]
				$mitarbeiter = $file_split[5]
				$mitarbeiteremail = $mitarbeiter + $emaildomain
				$datei = $file_split[-1]
				$datei_endung = $file.Extension
				$datei_ordner = $file.Directory.Name
				$root_path = "$file_split_0\$file_split_1\$file_split_2\$bereich\$abteilung\$mitarbeiter"
				$root_path_all = "$file_split_0\$file_split_1\$file_split_2\$bereich\$abteilung\$mitarbeiter\*"
				$finish_path = "$file_split_0\$file_split_1\freigegebene Daten\$bereich\$abteilung\$mitarbeiter\"
				$finish_file = "$finish_path$datei"				
				#Falls zuviele Unterordner, dann überspringe den Vorgang
				If ($file_split[8])
				{
					continue
				}		
				#Control-Logging-Eintrag erstellen
				$log_path = "d:\logs\control"
				$log_file = "$log_path\$datum_kurz.csv"
				$log_uhrzeit = (Get-Date).ToString("HH:mm:ss")
				$log_datum = get-date -Format "dd.MM.yyyy"			
				#Logeintrag - Objekt
				$log_eintrag = New-Object -TypeName PSObject
				$log_eintrag | Add-Member -Name "Datum" -MemberType Noteproperty -Value $log_datum
				$log_eintrag | Add-Member -Name "Uhrzeit" -MemberType Noteproperty -Value $log_uhrzeit
				$log_eintrag | Add-Member -Name "Mitarbeiter" -MemberType Noteproperty -Value $mitarbeiter
				$log_eintrag | Add-Member -Name "Datei" -MemberType Noteproperty -Value $datei			
				#prüfen ob Logverzeichnis existiert
				if (!(Test-Path $log_path))
				{
					New-Item -Path $log_path -ItemType Directory -Force
				}		
				#Logeintrag der Logdatei hinzufügen
				$log_eintrag | Export-Csv $log_file -Append -Delimiter ";" -NoTypeInformation -Force			
				#um welche Datei handelt es sich
				switch ($datei_endung)
				{				
					#Falls es eine AGENDA-Sicherung ist
					{ ($_ -eq ".ssi") -or ($_ -eq ".azi") -or ($_ -eq ".dsi") -or ($_ -eq ".rzi") }
					{
						#Deklaration der neuen Variablen
						$anzahl = $anzahl + 1
						$temp_path = "d:\temp\$mitarbeiter\$anzahl"
						$temp_file = "$temp_path\$datei"
						$unpack_path = "$temp_path\unpack_$anzahl"
						$arg = "-Dasi:`"$temp_file`""					
						#TuWas					
						#1. Erstelle den Temp-Pfad falls dieser noch nicht existiert - D:\temp\MA-Kürzel\Anzahl                               
						if (!(Test-Path $temp_path))
						{
							New-Item -Path $temp_path -ItemType Directory -Force
						}				
						#2. Verschiebe Datei in den Temp-Pfad
						Move-Item -Path $file -Destination $temp_path -Force				
						#3. Entpacke die Datensicherung
						$entpack = Start-Process -FilePath $dasiunpack -ArgumentList "-Dasi:$temp_file", "-Ziel:$unpack_path" -Wait -PassThru
						if ($entpack.ExitCode -ne 0)
						{
							$finish_path = "D:\Virenschutz\freigegebene Datensicherungen\!$datum_kurz\"
							$finish_file = "$finish_path$datei"
							$defekte_sic = "D:\Datensicherung_Defekt\$datum_kurz\"
							if (!(Test-Path $finish_path))
							{
								New-Item -Path $finish_path -ItemType Directory -Force
							}
							if (!(Test-Path $defekte_sic))
							{
								New-Item -Path $defekte_sic -ItemType Directory -Force
							}
							
							switch ($entpack.ExitCode)
							{
								1 { $entpack_fehler = "DASI-Parameter fehlt oder Quelldasi existiert nicht - Bitte bei MAB oder SR nachfragen" | Out-File -FilePath "$finish_file.txt" }
								2 { $entpack_fehler = "ZIEL-Parameter fehlt - Bitte bei MAB oder SR nachfragen" | Out-File -FilePath "$finish_file.txt" }
								3 { $entpack_fehler = "ZIEL-Verzeichnis konnte nicht angelegt werden - Bitte bei MAB oder SR nachfragen" | Out-File -FilePath "$finish_file.txt" }
								4 { $entpack_fehler = "FEHLER beim Löschen der DMS-Dokumente - Bitte bei MAB oder SR nachfragen" | Out-File -FilePath "$finish_file.txt" }
								5 { $entpack_fehler = "Beim Entpacken der Quelldatei sind Fehler aufgetreten.
Vermutlich wurde die Datensicherung nicht vollständig zu uns kopiert (Teamviewer etc.).
Die Datensicherung muss erneut geholt werden. (Kundenbereich - Dateiupload)
Evtl. ist auch die Quelldatensicherung beim Kunden bereits defekt.
In diesem Fall muss die Datensicherung erneut erstellt und übertragen werden.
Können die o.g. Fälle ausgeschlossen werden, bitte an MAB (174) oder SR (125) wenden.
" | Out-File -FilePath "$finish_file.txt" }
								6 { $entpack_fehler = "FEHLER beim Entpacken der DMS-Dokumente - Bitte bei MAB oder SR nachfragen" | Out-File -FilePath "$finish_file.txt" }
								7 { $entpack_fehler = "DASI-Parameter hat unerlaubten Dateityp - Bitte bei MAB oder SR nachfragen" | Out-File -FilePath "$finish_file.txt" }
								8 { $entpack_fehler = "FEHLER beim Entpacken der Lohn-Monatsabschluss-Zips - Bitte bei MAB oder SR nachfragen" | Out-File -FilePath "$finish_file.txt" }
							}			
							Copy-Item -Path $temp_file -Destination $defekte_sic -Force
							Remove-Item -Path $temp_file -Force
							Remove-Item -Path $temp_path -Force -Recurse
							break
						}			
						else
						{
							Write-Host "Bassd so"
						}				
						#4. Virenscannen  				
						$virenscan_log = "$path_log\Virenscans\$datum_kurz\$mitarbeiter-$anzahl.txt"
						$virenscan = Start-Process -FilePath $virenscanner1 -ArgumentList "/f=$unpack_path", "/pup", "/a", "/n", "/la=$virenscan_log", "/q=$quarantäne" -Wait -PassThru
						Add-Content $virenscan_log "`n"
						Add-Content $virenscan_log "$datei"					
						#4.1 Virus gefunden dann Email
						If ($virenscan.ExitCode -eq 1)
						{
							$emailBody_virus = @"
                                        Hallo,<br>
                                        <br>
                                        im Verzeichnis zur Virenpr&uuml;fung wurde ein Virus gefunden.<br>
                                        <br>
                                        Das Objekt $datei wurde unter Quarant&auml;ne gestellt.<br>
                                        <br>
                                        Die Technik ist bereits informiert <br>
                                        <br>
                                        Vielen Dank<br>
                                        <br>
                                        Das Virenpr&uuml;fteam<br>
                                    
"@
							Send-MailMessage -To $mitarbeiteremail -From $emailFrom -Subject "Virus in Datei $datei gefunden. Scanvorgang: $virenscan_log" -Body $emailBody_virus -SmtpServer $emailSmtpServer -BodyAsHtml
							Send-MailMessage -To "spam@agenda-software.de" -From $emailFrom -Subject "Virus in Datei $datei gefunden. Scanvorgang: $virenscan_log" -Body $emailBody_virus -SmtpServer $emailSmtpServer -BodyAsHtml
							Remove-Item -Path $unpack_path -Recurse -Force
							Remove-Item -Path $temp_file
							break
						}					
						#5. Unpack_x-Ordner löschen 
						Remove-Item -Path $unpack_path -Recurse -Force				
						#6. Überprüfung der Datei ob es sich wirklich um eine Dasi handelt und ggf. weitere Schritte einleiten													
						#Erstellen der Whitelist um zu prüfen, ob es sich wirklich um eine DASI handelt						
						$WhitelistAZI = "Lohn", "Dasi", "Fibu", "Korg", "ZMIV"				
						$Vorhanden = $Datei.Substring(0, 4)					
						#Falls der Dateiname mit der Whitlist übereinstimmt ergibt es ein Match und die Datei wird wie eine Datensicherung behandelt
						#ansonsten wird die Variable Datensicherung nicht gematcht und die Datei wird als normale Datei behandelt				
						if ($WhitelistAZI -contains $Vorhanden)
						{						
							$Datensicherung = $Datei						
						}				
						else
						{				
							$Datensicherung = "_not_gemacht_"						
						}				
						#Falls keine Datensicherung -> Mitarbeiterverzeichnis			
						If ($Datei -notmatch $Datensicherung)
						{
							$finish_path = "$file_split_0\$file_split_1\freigegebene Daten\$bereich\$abteilung\$mitarbeiter\"
							$finish_file = "$finish_path$datei"
							Move-Item -Path $temp_file -Destination $finish_file -Force
							break
						}			
						#7. Kundennummer herausfinden und Finishpfad bestimmen. Falls Pfad nicht existiert, dann anlegen
						$Kdnr = cmd /c $kdnr_tool $temp_file
						$sic_original = "D:\Datensicherung_O\$Kdnr\$datum_kurz\"
						$sic_file = "$sic_original$datei"
						$finish_path = "D:\Virenschutz\freigegebene Datensicherungen\$Kdnr\$datum_kurz\"
						$finish_file = "$finish_path$datei"
						$logfile = "D:\Virenschutz\freigegebene Datensicherungen\$Kdnr\$datei.txt"
						if (!(Test-Path $sic_original))
						{
							New-Item -Path $sic_original -ItemType Directory -Force
						}			
						if ($datei_endung -ne ".rzi")
						{		
							#7. Original-Datei nach Sic_Original kopieren                            
							Copy-Item -Path $temp_file -Destination $sic_file -Force					
							#8. Psydonymisieren der Temp-datei
							$psydo = Start-Process $psydo_tool -WorkingDirectory $psydo_tool_path -ArgumentList $arg -PassThru -Wait
							#8.1 Sollte ein Fehler passieren dann stelle eine Textdatei in das 
							If ($psydo.ExitCode -ne 0)
							{						
								switch ($psydo.ExitCode)
								{
									1 { $psydo_fehler = "Allgemeiner Fehler - Bitte bei MAB oder SR nachfragen" | Out-File -FilePath "$logfile" }
									2 { $psydo_fehler = "DASI-Parameter fehlt - Bitte bei MAB oder SR nachfragen" | Out-File -FilePath "$logfile" }
									3 { $psydo_fehler = "Quelldasi existiert nicht - Bitte bei MAB oder SR nachfragen" | Out-File -FilePath "$logfile" }
									4 { $psydo_fehler = "DASI-Parameter hat unerlaubten Dateityp - Bitte bei MAB oder SR nachfragen" | Out-File -FilePath "$logfile" }
									5 { $psydo_fehler = "ZIEL-Verzeichnis konnte nicht angelegt werden - Bitte bei MAB oder SR nachfragen" | Out-File -FilePath "$logfile" }
									6 { $psydo_fehler = "Beim Entpacken der Quelldatei sind Fehler aufgetreten.
Vermutlich wurde die Datensicherung nicht vollständig zu uns kopiert (Teamviewer etc.).
Die Datensicherung muss erneut geholt werden. (Kundenbereich - Dateiupload)
Evtl. ist auch die Quelldatensicherung beim Kunden bereits defekt.
In diesem Fall muss die Datensicherung erneut erstellt und übertragen werden.
Können die o.g. Fälle ausgeschlossen werden, bitte an MAB (174) oder interne-it@agenda-software.de wenden.
" | Out-File -FilePath "$logfile"
									}
									7 { $psydo_fehler = "Fehler beim Pseudonymisieren der Dasi - Bitte bei MAB oder SR nachfragen" | Out-File -FilePath "$logfile" }
									8 { $psydo_fehler = "Fehler beim Packen der Pseudo-Dasi - Bitte bei MAB oder SR nachfragen" | Out-File -FilePath "$logfile" }
								}	
							}			
						}	
						#9. Datei verschieben nach Finish-File
						if (!(Test-Path $finish_path))
						{
							New-Item -Path $finish_path -ItemType Directory -Force
						}		
						Copy-Item -Path $temp_file -Destination $finish_file -Force
						Remove-Item $temp_file -Force
						Remove-Item -Path $temp_path -Force -Recurse		
					}		
					#Falls es eine gepackte Datei ist
					{ ($_ -eq ".zip") -or ($_ -eq ".rar") -or ($_ -eq ".7z") -or ($_ -eq ".aif") }
					{			
						#Deklaration der Variablen
						$temp_path = "d:\temp\$mitarbeiter"
						$temp_file = "$temp_path\$datei"
						$unpack_path = "$temp_path\unpack_$anzahl"	
						#1. Erstelle Temp-Pfad falls dieser noch nicht existiert - D:\temp\MA-Kürzel  
						if (!(Test-Path $temp_path))
						{
							New-Item -Path $temp_path -ItemType Directory -Force
						}		
						#2. Datei in den Temp-Ordner verschieben
						Move-Item -Path $file -Destination $temp_path -Force		
						#3. Entpacke die Datei
						$entpack = Start-Process -FilePath $dasiunpack -ArgumentList "-Dasi:$temp_file", "-Ziel:$unpack_path" -Wait -PassThru
						if ($entpack.ExitCode -ne 0)
						{
							Write-Host "Fella bassiad: " $entpack.Exitcode
						}
						else
						{
							Write-Host "Bassd so"
						}		
						#4. Virenscannen
						$anzahl = $anzahl + 1
						$virenscan_log = "$path_log\Virenscans\$datum_kurz\$mitarbeiter-$anzahl.txt"
						$virenscan = Start-Process -FilePath $virenscanner1 -ArgumentList "/f=$unpack_path", "/pup", "/a", "/n", "/la=$virenscan_log", "/q=$quarantäne" -Wait -PassThru
						Add-Content $virenscan_log "`n"
						Add-Content $virenscan_log "$datei"		
						#4.1 Virus gefunden -> Email
						If ($virenscan.ExitCode -eq 1)
						{
							$emailBody_virus = @"
                                        Hallo,<br>
                                        <br>
                                        im Verzeichnis zur Virenpr&uuml;fung wurde ein Virus gefunden.<br>
                                        <br>
                                        Das Objekt $datei wurde unter Quarant&auml;ne gestellt.<br>
                                        <br>
                                        Die Technik ist bereits informiert <br>
                                        <br>
                                        Vielen Dank<br>
                                        <br>
                                        Das Virenpr&uuml;fteam<br>
                                    
"@
							Send-MailMessage -To $mitarbeiteremail -From $emailFrom -Subject "Virus in Datei $datei gefunden. Scanvorgang: $virenscan_log" -Body $emailBody_virus -SmtpServer $emailSmtpServer -BodyAsHtml
							Send-MailMessage -To "spam@agenda-software.de" -From $emailFrom -Subject "Virus in Datei $datei gefunden. Scanvorgang: $virenscan_log" -Body $emailBody_virus -SmtpServer $emailSmtpServer -BodyAsHtml
							Remove-Item -Path $unpack_path -Recurse -Force
							Remove-Item -Path $temp_file
							break
						}
						#5. Unpack-Ordner löschen und Datei verschieben
						Remove-Item -Path $unpack_path -Recurse -Force
						Move-Item -Path $temp_file -Destination $finish_file -Force	
					}
					#Alle anderen Dateien
					default
					{
						$temp_path = "d:\temp\$mitarbeiter"				
						#Erstelle Temp-Pfad falls dieser noch nicht existiert - D:\temp\MA-Kürzel                        
						if (!(Test-Path $temp_path))
						{
							New-Item -Path $temp_path -ItemType Directory -Force
						}		
						#Datei oder Ordner
						if (!(Test-Path $file.Directory))
						{
							Break
						}				
						#Sollte der Root-Pfad nicht der Datei-Pfad sein, dann handelt es sich um eine Datei im Unterordner
						if ($root_path -ne $file.Directory)			
						#Wenn es sich um einen Ordner handelt
						{
							$temp_folder = "$temp_path\$datei_ordner"
							$temp_file = "$temp_folder\$datei"
							$argument1 = '/f=' + '"' + $temp_folder + '"'		
							#Ordner verschieben nach Temp
							Move-Item -Path "$root_path\$datei_ordner" -Destination "$temp_path" -Force
							#Virenscannen
							$anzahl = $anzahl + 1
							$virenscan_log = "$path_log\Virenscans\$datum_kurz\$mitarbeiter-$anzahl.txt"
							$virenscan = Start-Process -FilePath $virenscanner1 -ArgumentList $argument1, "/pup", "/a", "/n", "/la=$virenscan_log", "/q=$quarantäne" -Wait -PassThru
							Add-Content $virenscan_log "`n"
							Add-Content $virenscan_log "$datei"
							#Virus gefunden -> Email	
							If ($virenscan.ExitCode -eq 1)
							{
								$emailBody_virus = @"
                                Hallo,<br>
                                <br>
                                im Verzeichnis zur Virenpr&uuml;fung wurde ein Virus gefunden.<br>
                                <br>
                                Das Objekt $datei wurde unter Quarant&auml;ne gestellt.<br>
                                <br>
                                Die Technik ist bereits informiert <br>
                                <br>
                                Vielen Dank<br>
                                <br>
                                Das Virenpr&uuml;fteam<br>
                                    
"@
								Send-MailMessage -To $mitarbeiteremail -From $emailFrom -Subject "Virus in Datei $datei gefunden. Scanvorgang: $virenscan_log" -Body $emailBody_virus -SmtpServer $emailSmtpServer -BodyAsHtml
								Send-MailMessage -To "spam@agenda-software.de" -From $emailFrom -Subject "Virus in Datei $datei gefunden. Scanvorgang: $virenscan_log" -Body $emailBody_virus -SmtpServer $emailSmtpServer -BodyAsHtml	
								break
							}
							#Ordner verschieben nach gescannt
							Move-Item -Path $temp_folder -Destination $finish_path -Force	
						}	
						else
						#Wenn es sich um eine Datei handelt
						{
							$temp_file = "$temp_path\$datei"
							$argument1 = '/f=' + '"' + $temp_file + '"'
							#Datei verschieben nach Temp
							Move-Item -Path $file -Destination $temp_path -Force
							#Virenscannen
							$anzahl = $anzahl + 1
							$virenscan_log = "$path_log\Virenscans\$datum_kurz\$mitarbeiter-$anzahl.txt"
							$virenscan = Start-Process -FilePath $virenscanner1 -ArgumentList $argument1, "/pup", "/a", "/n", "/la=$virenscan_log", "/q=$quarantäne" -Wait -PassThru
							Add-Content $virenscan_log "`n"
							Add-Content $virenscan_log "$datei"		
							#Virus gefunden -> Email		
							If ($virenscan.ExitCode -eq 1)
							{
								$emailBody_virus = @"
                            Hallo,<br>
                            <br>
                            im Verzeichnis zur Virenpr&uuml;fung wurde ein Virus gefunden.<br>
                            <br>
                            Das Objekt $datei wurde unter Quarant&auml;ne gestellt.<br>
                            <br>
                            Die Technik ist bereits informiert <br>
                            <br>
                            Vielen Dank<br>
                            <br>
                            Das Virenpr&uuml;fteam<br>
                                    
"@
								Send-MailMessage -To $mitarbeiteremail -From $emailFrom -Subject "Virus in Datei $datei gefunden. Scanvorgang: $virenscan_log" -Body $emailBody_virus -SmtpServer $emailSmtpServer -BodyAsHtml
								Send-MailMessage -To "spam@agenda-software.de" -From $emailFrom -Subject "Virus in Datei $datei gefunden. Scanvorgang: $virenscan_log" -Body $emailBody_virus -SmtpServer $emailSmtpServer -BodyAsHtml
								break
							}	
							#Datei verschieben nach gescannt
							Move-Item -Path "$temp_path\$datei" -Destination $finish_file -Force			
						}	
					}	
				}	
			}
		}
	}
	#Schreiben der "ich-bin-am-Leben-Datei"
	$files | Out-File "D:\logs\alive.txt"
	#Pause bis zum nächsten Durchlauf
	Start-Sleep -Seconds 30
}
