from Crypto.Util.number import *
from gmpy2 import *
import math
import numpy as np
from mpmath import *

c = 1220012318588871886132524757898884422174534558055593713309088304910273991073554732659977133980685370899257850121970812405700793710546674062154237544840177616746805668666317481140872605653768484867292138139949076102907399831998827567645230986345455915692863094364797526497302082734955903755050638155202890599808146956044568639690002921620304969196755223769438221859424275683828638207433071955615349052424040706261639770492033970498727183446507482899334169592311953247661557664109356372049286283480939368007035616954029177541731719684026988849403756133033533171081378815289443019437298879607294287249591634702823432448559878065453908423094452047188125358790554039587941488937855941604809869090304206028751113018999782990033393577325766685647733181521675994939066814158759362046052998582186178682593597175186539419118605277037256659707217066953121398700583644564201414551200278389319378027058801216150663695102005048597466358061508725332471930736629781191567057009302022382219283560795941554288119544255055962
n = 1615765684321463054078226051959887884233678317734892901740763321135213636796075462401950274602405095138589898087428337758445013281488966866073355710771864671726991918706558071231266976427184673800225254531695928541272546385146495736420261815693810544589811104967829354461491178200126099661909654163542661541699404839644035177445092988952614918424317082380174383819025585076206641993479326576180793544321194357018916215113009742654408597083724508169216182008449693917227497813165444372201517541788989925461711067825681947947471001390843774746442699739386923285801022685451221261010798837646928092277556198145662924691803032880040492762442561497760689933601781401617086600593482127465655390841361154025890679757514060456103104199255917164678161972735858939464790960448345988941481499050248673128656508055285037090026439683847266536283160142071643015434813473463469733112182328678706702116054036618277506997666534567846763938692335069955755244438415377933440029498378955355877502743215305768814857864433151287
e = 3

# c = m ** e % n
# c = m ** e - d * n
# m = c+d*n**e

d = 1
while True:
    m, exact = gmpy2.iroot(d*n + c, e)
    if exact:
        print(m)
        print(long_to_bytes(m))
    d += 1
