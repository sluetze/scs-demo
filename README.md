# scs-demo
This Demo runs on Openshift and showcases an example of a supply chain for Container Images which should be compliant to BSI

# Scope
Die Demo umfasst den Prozess der Uebernahme von Images von Dritten, sowie die erstellung von Internen Anwendung an einem Beispiel. Es wird hierbei darauf eingegangen, an welchen Stellen Policies wirken und geprueft werden. Ebenfalls wird gezeigt, an welchen Stellen Anpassungen fuer die Adaption in einem Unternehmen durchgefuehrt werden muessen. Die Demo ist als Geruest ausgelegt, was fuer die Diskussion der Thematik dient, aber auch ausgangspunkt fuer die Uebernahme in den eigenen Betrieb sein kann. Es wird jedoch nicht garantiert, dass alle Anforderungen des BSI Pruefsicher addressiert sind. Die Ausformulierungen der IG BvC werden beruecksichtigt.
Die Demo umfasst damit einen beispielprozess der Erstellung, Uebernahme, Pruefung und Veroeffentlichung von Container-Images unter Nutzung von Red Hat Technologie.
Die Demo nutzt logische Trennungsmechanismen wo moeglich (bspw. Statt Trennung von Test und Produktiv-Images in eigenen Registries, wird dies lediglich in Repositories durchgefuehrt)

# Out of Scope
Die Demo umfasst keine BSI Anforderungen, die die Infrastruktur betreffen (z.B. Netzsegmentierung)
Die Demo fuehrt keine physischen Trennungen ein
Die Demo beruecksichtigt keine Air-Gapped Szenarien explizit
Die Demo hat nicht den Anspruch komplett on-premise laufen zu koennen. OnPrem sollte jedoch kein Problem sein, wenn man die Onlinekomponenten austauscht (Git, Quay, ...)