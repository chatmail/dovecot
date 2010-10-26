/*
 * OTP standard dictionary.
 *
 * Copyright (c) 2006 Andrey Panin <pazke@donpac.ru>
 *
 * This software is released under the MIT license.
 */

#include "lib.h"
#include "otp.h"

#include <string.h>

struct hint {
	const short l, u;
};

static const struct hint hints[] = {
	{ 0,	114 },		/* A */
	{ 114,	292 },		/* B */
	{ 292,	415 },		/* C */
	{ 415,	528 },		/* D */
	{ 528,	575 },		/* E */
	{ 575,	687 },		/* F */
	{ 687,	792 },		/* G */
	{ 792,	922 },		/* H */
	{ 922,	958 },		/* I */
	{ 958,	1014 },		/* J */
	{ 1014,	1055 },		/* K */
	{ 1055,	1189 },		/* L */
	{ 1189,	1315 },		/* M */
	{ 1315,	1383 },		/* N */
	{ 1383,	1446 },		/* O */
	{ 1446,	1482 },		/* P */
	{ 1482,	1486 },		/* Q */
	{ 1486,	1597 },		/* R */
	{ 1597,	1777 },		/* S */
	{ 1777,	1900 },		/* T */
	{ 1900,	1911 },		/* U */
	{ 1911,	1937 },		/* V */
	{ 1937,	2028 },		/* W */
	{ 0,	0 },		/* X */
	{ 2028,	2048 },		/* Y */
};

struct word {
	const short value;
	const char word[4];
};

static const struct word dictionary[2048] = {
	{    0, "A"    }, {    1, "ABE"  }, {  571, "ABED" }, {  572, "ABEL" },
	{  573, "ABET" }, {  574, "ABLE" }, {  575, "ABUT" }, {    2, "ACE"  },
	{  576, "ACHE" }, {  577, "ACID" }, {  578, "ACME" }, {  579, "ACRE" },
	{    3, "ACT"  }, {  580, "ACTA" }, {  581, "ACTS" }, {    4, "AD"   },
	{    5, "ADA"  }, {  582, "ADAM" }, {    6, "ADD"  }, {  583, "ADDS" },
	{  584, "ADEN" }, {  585, "AFAR" }, {  586, "AFRO" }, {  587, "AGEE" },
	{    7, "AGO"  }, {  588, "AHEM" }, {  589, "AHOY" }, {    8, "AID"  },
	{  590, "AIDA" }, {  591, "AIDE" }, {  592, "AIDS" }, {    9, "AIM"  },
	{   10, "AIR"  }, {  593, "AIRY" }, {  594, "AJAR" }, {  595, "AKIN" },
	{  596, "ALAN" }, {  597, "ALEC" }, {  598, "ALGA" }, {  599, "ALIA" },
	{   11, "ALL"  }, {  600, "ALLY" }, {  601, "ALMA" }, {  602, "ALOE" },
	{   12, "ALP"  }, {  603, "ALSO" }, {  604, "ALTO" }, {  605, "ALUM" },
	{  606, "ALVA" }, {   13, "AM"   }, {  607, "AMEN" }, {  608, "AMES" },
	{  609, "AMID" }, {  610, "AMMO" }, {  611, "AMOK" }, {  612, "AMOS" },
	{  613, "AMRA" }, {   14, "AMY"  }, {   15, "AN"   }, {   16, "ANA"  },
	{   17, "AND"  }, {  614, "ANDY" }, {  615, "ANEW" }, {   18, "ANN"  },
	{  616, "ANNA" }, {  617, "ANNE" }, {   19, "ANT"  }, {  618, "ANTE" },
	{  619, "ANTI" }, {   20, "ANY"  }, {   21, "APE"  }, {   22, "APS"  },
	{   23, "APT"  }, {  620, "AQUA" }, {  621, "ARAB" }, {   24, "ARC"  },
	{  622, "ARCH" }, {   25, "ARE"  }, {  623, "AREA" }, {  624, "ARGO" },
	{  625, "ARID" }, {   26, "ARK"  }, {   27, "ARM"  }, {  626, "ARMY" },
	{   28, "ART"  }, {  627, "ARTS" }, {  628, "ARTY" }, {   29, "AS"   },
	{   30, "ASH"  }, {  629, "ASIA" }, {   31, "ASK"  }, {  630, "ASKS" },
	{   32, "AT"   }, {   33, "ATE"  }, {  631, "ATOM" }, {   34, "AUG"  },
	{   35, "AUK"  }, {  632, "AUNT" }, {  633, "AURA" }, {  634, "AUTO" },
	{   36, "AVE"  }, {  635, "AVER" }, {  636, "AVID" }, {  637, "AVIS" },
	{  638, "AVON" }, {  639, "AVOW" }, {  640, "AWAY" }, {   37, "AWE"  },
	{   38, "AWK"  }, {   39, "AWL"  }, {   40, "AWN"  }, {  641, "AWRY" },
	{   41, "AX"   }, {   42, "AYE"  }, {  642, "BABE" }, {  643, "BABY" },
	{  644, "BACH" }, {  645, "BACK" }, {   43, "BAD"  }, {  646, "BADE" },
	{   44, "BAG"  }, {   45, "BAH"  }, {  647, "BAIL" }, {  648, "BAIT" },
	{  649, "BAKE" }, {  650, "BALD" }, {  651, "BALE" }, {  652, "BALI" },
	{  653, "BALK" }, {  654, "BALL" }, {  655, "BALM" }, {   46, "BAM"  },
	{   47, "BAN"  }, {  656, "BAND" }, {  657, "BANE" }, {  658, "BANG" },
	{  659, "BANK" }, {   48, "BAR"  }, {  660, "BARB" }, {  661, "BARD" },
	{  662, "BARE" }, {  663, "BARK" }, {  664, "BARN" }, {  665, "BARR" },
	{  666, "BASE" }, {  667, "BASH" }, {  668, "BASK" }, {  669, "BASS" },
	{   49, "BAT"  }, {  670, "BATE" }, {  671, "BATH" }, {  672, "BAWD" },
	{  673, "BAWL" }, {   50, "BAY"  }, {   51, "BE"   }, {  674, "BEAD" },
	{  675, "BEAK" }, {  676, "BEAM" }, {  677, "BEAN" }, {  678, "BEAR" },
	{  679, "BEAT" }, {  680, "BEAU" }, {  681, "BECK" }, {   52, "BED"  },
	{   53, "BEE"  }, {  682, "BEEF" }, {  683, "BEEN" }, {  684, "BEER" },
	{  685, "BEET" }, {   54, "BEG"  }, {  686, "BELA" }, {  687, "BELL" },
	{  688, "BELT" }, {   55, "BEN"  }, {  689, "BEND" }, {  690, "BENT" },
	{  691, "BERG" }, {  692, "BERN" }, {  693, "BERT" }, {  694, "BESS" },
	{  695, "BEST" }, {   56, "BET"  }, {  696, "BETA" }, {  697, "BETH" },
	{   57, "BEY"  }, {  698, "BHOY" }, {  699, "BIAS" }, {   58, "BIB"  },
	{   59, "BID"  }, {  700, "BIDE" }, {  701, "BIEN" }, {   60, "BIG"  },
	{  702, "BILE" }, {  703, "BILK" }, {  704, "BILL" }, {   61, "BIN"  },
	{  705, "BIND" }, {  706, "BING" }, {  707, "BIRD" }, {   62, "BIT"  },
	{  708, "BITE" }, {  709, "BITS" }, {  710, "BLAB" }, {  711, "BLAT" },
	{  712, "BLED" }, {  713, "BLEW" }, {  714, "BLOB" }, {  715, "BLOC" },
	{  716, "BLOT" }, {  717, "BLOW" }, {  718, "BLUE" }, {  719, "BLUM" },
	{  720, "BLUR" }, {  721, "BOAR" }, {  722, "BOAT" }, {   63, "BOB"  },
	{  723, "BOCA" }, {  724, "BOCK" }, {  725, "BODE" }, {  726, "BODY" },
	{   64, "BOG"  }, {  727, "BOGY" }, {  728, "BOHR" }, {  729, "BOIL" },
	{  730, "BOLD" }, {  731, "BOLO" }, {  732, "BOLT" }, {  733, "BOMB" },
	{   65, "BON"  }, {  734, "BONA" }, {  735, "BOND" }, {  736, "BONE" },
	{  737, "BONG" }, {  738, "BONN" }, {  739, "BONY" }, {   66, "BOO"  },
	{  740, "BOOK" }, {  741, "BOOM" }, {  742, "BOON" }, {  743, "BOOT" },
	{   67, "BOP"  }, {  744, "BORE" }, {  745, "BORG" }, {  746, "BORN" },
	{  747, "BOSE" }, {  748, "BOSS" }, {  749, "BOTH" }, {  750, "BOUT" },
	{   68, "BOW"  }, {  751, "BOWL" }, {   69, "BOY"  }, {  752, "BOYD" },
	{  753, "BRAD" }, {  754, "BRAE" }, {  755, "BRAG" }, {  756, "BRAN" },
	{  757, "BRAY" }, {  758, "BRED" }, {  759, "BREW" }, {  760, "BRIG" },
	{  761, "BRIM" }, {  762, "BROW" }, {   70, "BUB"  }, {  763, "BUCK" },
	{   71, "BUD"  }, {  764, "BUDD" }, {  765, "BUFF" }, {   72, "BUG"  },
	{  766, "BULB" }, {  767, "BULK" }, {  768, "BULL" }, {   73, "BUM"  },
	{   74, "BUN"  }, {  769, "BUNK" }, {  770, "BUNT" }, {  771, "BUOY" },
	{  772, "BURG" }, {  773, "BURL" }, {  774, "BURN" }, {  775, "BURR" },
	{  776, "BURT" }, {  777, "BURY" }, {   75, "BUS"  }, {  778, "BUSH" },
	{  779, "BUSS" }, {  780, "BUST" }, {  781, "BUSY" }, {   76, "BUT"  },
	{   77, "BUY"  }, {   78, "BY"   }, {   79, "BYE"  }, {  782, "BYTE" },
	{   80, "CAB"  }, {  783, "CADY" }, {  784, "CAFE" }, {  785, "CAGE" },
	{  786, "CAIN" }, {  787, "CAKE" }, {   81, "CAL"  }, {  788, "CALF" },
	{  789, "CALL" }, {  790, "CALM" }, {   82, "CAM"  }, {  791, "CAME" },
	{   83, "CAN"  }, {  792, "CANE" }, {  793, "CANT" }, {   84, "CAP"  },
	{   85, "CAR"  }, {  794, "CARD" }, {  795, "CARE" }, {  796, "CARL" },
	{  797, "CARR" }, {  798, "CART" }, {  799, "CASE" }, {  800, "CASH" },
	{  801, "CASK" }, {  802, "CAST" }, {   86, "CAT"  }, {  803, "CAVE" },
	{   87, "CAW"  }, {  804, "CEIL" }, {  805, "CELL" }, {  806, "CENT" },
	{  807, "CERN" }, {  808, "CHAD" }, {  809, "CHAR" }, {  810, "CHAT" },
	{  811, "CHAW" }, {  812, "CHEF" }, {  813, "CHEN" }, {  814, "CHEW" },
	{  815, "CHIC" }, {  816, "CHIN" }, {  817, "CHOU" }, {  818, "CHOW" },
	{  819, "CHUB" }, {  820, "CHUG" }, {  821, "CHUM" }, {  822, "CITE" },
	{  823, "CITY" }, {  824, "CLAD" }, {  825, "CLAM" }, {  826, "CLAN" },
	{  827, "CLAW" }, {  828, "CLAY" }, {  829, "CLOD" }, {  830, "CLOG" },
	{  831, "CLOT" }, {  832, "CLUB" }, {  833, "CLUE" }, {  834, "COAL" },
	{  835, "COAT" }, {  836, "COCA" }, {  837, "COCK" }, {  838, "COCO" },
	{   88, "COD"  }, {  839, "CODA" }, {  840, "CODE" }, {  841, "CODY" },
	{  842, "COED" }, {   89, "COG"  }, {  843, "COIL" }, {  844, "COIN" },
	{  845, "COKE" }, {   90, "COL"  }, {  846, "COLA" }, {  847, "COLD" },
	{  848, "COLT" }, {  849, "COMA" }, {  850, "COMB" }, {  851, "COME" },
	{   91, "CON"  }, {   92, "COO"  }, {  852, "COOK" }, {  853, "COOL" },
	{  854, "COON" }, {  855, "COOT" }, {   93, "COP"  }, {  856, "CORD" },
	{  857, "CORE" }, {  858, "CORK" }, {  859, "CORN" }, {  860, "COST" },
	{   94, "COT"  }, {  861, "COVE" }, {   95, "COW"  }, {  862, "COWL" },
	{   96, "COY"  }, {  863, "CRAB" }, {  864, "CRAG" }, {  865, "CRAM" },
	{  866, "CRAY" }, {  867, "CREW" }, {  868, "CRIB" }, {  869, "CROW" },
	{  870, "CRUD" }, {   97, "CRY"  }, {   98, "CUB"  }, {  871, "CUBA" },
	{  872, "CUBE" }, {   99, "CUE"  }, {  873, "CUFF" }, {  874, "CULL" },
	{  875, "CULT" }, {  876, "CUNY" }, {  100, "CUP"  }, {  101, "CUR"  },
	{  877, "CURB" }, {  878, "CURD" }, {  879, "CURE" }, {  880, "CURL" },
	{  881, "CURT" }, {  102, "CUT"  }, {  882, "CUTS" }, {  103, "DAB"  },
	{  104, "DAD"  }, {  883, "DADE" }, {  884, "DALE" }, {  105, "DAM"  },
	{  885, "DAME" }, {  106, "DAN"  }, {  886, "DANA" }, {  887, "DANE" },
	{  888, "DANG" }, {  889, "DANK" }, {  107, "DAR"  }, {  890, "DARE" },
	{  891, "DARK" }, {  892, "DARN" }, {  893, "DART" }, {  894, "DASH" },
	{  895, "DATA" }, {  896, "DATE" }, {  897, "DAVE" }, {  898, "DAVY" },
	{  899, "DAWN" }, {  108, "DAY"  }, {  900, "DAYS" }, {  901, "DEAD" },
	{  902, "DEAF" }, {  903, "DEAL" }, {  904, "DEAN" }, {  905, "DEAR" },
	{  906, "DEBT" }, {  907, "DECK" }, {  109, "DEE"  }, {  908, "DEED" },
	{  909, "DEEM" }, {  910, "DEER" }, {  911, "DEFT" }, {  912, "DEFY" },
	{  110, "DEL"  }, {  913, "DELL" }, {  111, "DEN"  }, {  914, "DENT" },
	{  915, "DENY" }, {  112, "DES"  }, {  916, "DESK" }, {  113, "DEW"  },
	{  917, "DIAL" }, {  918, "DICE" }, {  114, "DID"  }, {  115, "DIE"  },
	{  919, "DIED" }, {  920, "DIET" }, {  116, "DIG"  }, {  921, "DIME" },
	{  117, "DIN"  }, {  922, "DINE" }, {  923, "DING" }, {  924, "DINT" },
	{  118, "DIP"  }, {  925, "DIRE" }, {  926, "DIRT" }, {  927, "DISC" },
	{  928, "DISH" }, {  929, "DISK" }, {  930, "DIVE" }, {  119, "DO"   },
	{  931, "DOCK" }, {  120, "DOE"  }, {  932, "DOES" }, {  121, "DOG"  },
	{  933, "DOLE" }, {  934, "DOLL" }, {  935, "DOLT" }, {  936, "DOME" },
	{  122, "DON"  }, {  937, "DONE" }, {  938, "DOOM" }, {  939, "DOOR" },
	{  940, "DORA" }, {  941, "DOSE" }, {  123, "DOT"  }, {  942, "DOTE" },
	{  943, "DOUG" }, {  944, "DOUR" }, {  945, "DOVE" }, {  124, "DOW"  },
	{  946, "DOWN" }, {  947, "DRAB" }, {  948, "DRAG" }, {  949, "DRAM" },
	{  950, "DRAW" }, {  951, "DREW" }, {  952, "DRUB" }, {  953, "DRUG" },
	{  954, "DRUM" }, {  125, "DRY"  }, {  955, "DUAL" }, {  126, "DUB"  },
	{  956, "DUCK" }, {  957, "DUCT" }, {  127, "DUD"  }, {  128, "DUE"  },
	{  958, "DUEL" }, {  959, "DUET" }, {  129, "DUG"  }, {  960, "DUKE" },
	{  961, "DULL" }, {  962, "DUMB" }, {  130, "DUN"  }, {  963, "DUNE" },
	{  964, "DUNK" }, {  965, "DUSK" }, {  966, "DUST" }, {  967, "DUTY" },
	{  968, "EACH" }, {  131, "EAR"  }, {  969, "EARL" }, {  970, "EARN" },
	{  971, "EASE" }, {  972, "EAST" }, {  973, "EASY" }, {  132, "EAT"  },
	{  974, "EBEN" }, {  975, "ECHO" }, {  133, "ED"   }, {  976, "EDDY" },
	{  977, "EDEN" }, {  978, "EDGE" }, {  979, "EDGY" }, {  980, "EDIT" },
	{  981, "EDNA" }, {  134, "EEL"  }, {  982, "EGAN" }, {  135, "EGG"  },
	{  136, "EGO"  }, {  983, "ELAN" }, {  984, "ELBA" }, {  137, "ELI"  },
	{  138, "ELK"  }, {  985, "ELLA" }, {  139, "ELM"  }, {  986, "ELSE" },
	{  140, "ELY"  }, {  141, "EM"   }, {  987, "EMIL" }, {  988, "EMIT" },
	{  989, "EMMA" }, {  142, "END"  }, {  990, "ENDS" }, {  991, "ERIC" },
	{  992, "EROS" }, {  143, "EST"  }, {  144, "ETC"  }, {  145, "EVA"  },
	{  146, "EVE"  }, {  993, "EVEN" }, {  994, "EVER" }, {  995, "EVIL" },
	{  147, "EWE"  }, {  148, "EYE"  }, {  996, "EYED" }, {  997, "FACE" },
	{  998, "FACT" }, {  149, "FAD"  }, {  999, "FADE" }, { 1000, "FAIL" },
	{ 1001, "FAIN" }, { 1002, "FAIR" }, { 1003, "FAKE" }, { 1004, "FALL" },
	{ 1005, "FAME" }, {  150, "FAN"  }, { 1006, "FANG" }, {  151, "FAR"  },
	{ 1007, "FARM" }, { 1008, "FAST" }, {  152, "FAT"  }, { 1009, "FATE" },
	{ 1010, "FAWN" }, {  153, "FAY"  }, { 1011, "FEAR" }, { 1012, "FEAT" },
	{  154, "FED"  }, {  155, "FEE"  }, { 1013, "FEED" }, { 1014, "FEEL" },
	{ 1015, "FEET" }, { 1016, "FELL" }, { 1017, "FELT" }, { 1018, "FEND" },
	{ 1019, "FERN" }, { 1020, "FEST" }, { 1021, "FEUD" }, {  156, "FEW"  },
	{  157, "FIB"  }, { 1022, "FIEF" }, {  158, "FIG"  }, { 1023, "FIGS" },
	{ 1024, "FILE" }, { 1025, "FILL" }, { 1026, "FILM" }, {  159, "FIN"  },
	{ 1027, "FIND" }, { 1028, "FINE" }, { 1029, "FINK" }, {  160, "FIR"  },
	{ 1030, "FIRE" }, { 1031, "FIRM" }, { 1032, "FISH" }, { 1033, "FISK" },
	{ 1034, "FIST" }, {  161, "FIT"  }, { 1035, "FITS" }, { 1036, "FIVE" },
	{ 1037, "FLAG" }, { 1038, "FLAK" }, { 1039, "FLAM" }, { 1040, "FLAT" },
	{ 1041, "FLAW" }, { 1042, "FLEA" }, { 1043, "FLED" }, { 1044, "FLEW" },
	{ 1045, "FLIT" }, {  162, "FLO"  }, { 1046, "FLOC" }, { 1047, "FLOG" },
	{ 1048, "FLOW" }, { 1049, "FLUB" }, { 1050, "FLUE" }, {  163, "FLY"  },
	{ 1051, "FOAL" }, { 1052, "FOAM" }, {  164, "FOE"  }, {  165, "FOG"  },
	{ 1053, "FOGY" }, { 1054, "FOIL" }, { 1055, "FOLD" }, { 1056, "FOLK" },
	{ 1057, "FOND" }, { 1058, "FONT" }, { 1059, "FOOD" }, { 1060, "FOOL" },
	{ 1061, "FOOT" }, {  166, "FOR"  }, { 1062, "FORD" }, { 1063, "FORE" },
	{ 1064, "FORK" }, { 1065, "FORM" }, { 1066, "FORT" }, { 1067, "FOSS" },
	{ 1068, "FOUL" }, { 1069, "FOUR" }, { 1070, "FOWL" }, { 1071, "FRAU" },
	{ 1072, "FRAY" }, { 1073, "FRED" }, { 1074, "FREE" }, { 1075, "FRET" },
	{ 1076, "FREY" }, { 1077, "FROG" }, { 1078, "FROM" }, {  167, "FRY"  },
	{ 1079, "FUEL" }, { 1080, "FULL" }, {  168, "FUM"  }, { 1081, "FUME" },
	{  169, "FUN"  }, { 1082, "FUND" }, { 1083, "FUNK" }, {  170, "FUR"  },
	{ 1084, "FURY" }, { 1085, "FUSE" }, { 1086, "FUSS" }, {  171, "GAB"  },
	{  172, "GAD"  }, { 1087, "GAFF" }, {  173, "GAG"  }, { 1088, "GAGE" },
	{ 1089, "GAIL" }, { 1090, "GAIN" }, { 1091, "GAIT" }, {  174, "GAL"  },
	{ 1092, "GALA" }, { 1093, "GALE" }, { 1094, "GALL" }, { 1095, "GALT" },
	{  175, "GAM"  }, { 1096, "GAME" }, { 1097, "GANG" }, {  176, "GAP"  },
	{ 1098, "GARB" }, { 1099, "GARY" }, {  177, "GAS"  }, { 1100, "GASH" },
	{ 1101, "GATE" }, { 1102, "GAUL" }, { 1103, "GAUR" }, { 1104, "GAVE" },
	{ 1105, "GAWK" }, {  178, "GAY"  }, { 1106, "GEAR" }, {  179, "GEE"  },
	{  180, "GEL"  }, { 1107, "GELD" }, {  181, "GEM"  }, { 1108, "GENE" },
	{ 1109, "GENT" }, { 1110, "GERM" }, {  182, "GET"  }, { 1111, "GETS" },
	{ 1112, "GIBE" }, { 1113, "GIFT" }, {  183, "GIG"  }, {  184, "GIL"  },
	{ 1114, "GILD" }, { 1115, "GILL" }, { 1116, "GILT" }, {  185, "GIN"  },
	{ 1117, "GINA" }, { 1118, "GIRD" }, { 1119, "GIRL" }, { 1120, "GIST" },
	{ 1121, "GIVE" }, { 1122, "GLAD" }, { 1123, "GLEE" }, { 1124, "GLEN" },
	{ 1125, "GLIB" }, { 1126, "GLOB" }, { 1127, "GLOM" }, { 1128, "GLOW" },
	{ 1129, "GLUE" }, { 1130, "GLUM" }, { 1131, "GLUT" }, {  186, "GO"   },
	{ 1132, "GOAD" }, { 1133, "GOAL" }, { 1134, "GOAT" }, { 1135, "GOER" },
	{ 1136, "GOES" }, { 1137, "GOLD" }, { 1138, "GOLF" }, { 1139, "GONE" },
	{ 1140, "GONG" }, { 1141, "GOOD" }, { 1142, "GOOF" }, { 1143, "GORE" },
	{ 1144, "GORY" }, { 1145, "GOSH" }, {  187, "GOT"  }, { 1146, "GOUT" },
	{ 1147, "GOWN" }, { 1148, "GRAB" }, { 1149, "GRAD" }, { 1150, "GRAY" },
	{ 1151, "GREG" }, { 1152, "GREW" }, { 1153, "GREY" }, { 1154, "GRID" },
	{ 1155, "GRIM" }, { 1156, "GRIN" }, { 1157, "GRIT" }, { 1158, "GROW" },
	{ 1159, "GRUB" }, { 1160, "GULF" }, { 1161, "GULL" }, {  188, "GUM"  },
	{  189, "GUN"  }, { 1162, "GUNK" }, { 1163, "GURU" }, {  190, "GUS"  },
	{ 1164, "GUSH" }, { 1165, "GUST" }, {  191, "GUT"  }, {  192, "GUY"  },
	{ 1166, "GWEN" }, { 1167, "GWYN" }, {  193, "GYM"  }, {  194, "GYP"  },
	{  195, "HA"   }, { 1168, "HAAG" }, { 1169, "HAAS" }, { 1170, "HACK" },
	{  196, "HAD"  }, { 1171, "HAIL" }, { 1172, "HAIR" }, {  197, "HAL"  },
	{ 1173, "HALE" }, { 1174, "HALF" }, { 1175, "HALL" }, { 1176, "HALO" },
	{ 1177, "HALT" }, {  198, "HAM"  }, {  199, "HAN"  }, { 1178, "HAND" },
	{ 1179, "HANG" }, { 1180, "HANK" }, { 1181, "HANS" }, {  200, "HAP"  },
	{ 1182, "HARD" }, { 1183, "HARK" }, { 1184, "HARM" }, { 1185, "HART" },
	{  201, "HAS"  }, { 1186, "HASH" }, { 1187, "HAST" }, {  202, "HAT"  },
	{ 1188, "HATE" }, { 1189, "HATH" }, { 1190, "HAUL" }, { 1191, "HAVE" },
	{  203, "HAW"  }, { 1192, "HAWK" }, {  204, "HAY"  }, { 1193, "HAYS" },
	{  205, "HE"   }, { 1194, "HEAD" }, { 1195, "HEAL" }, { 1196, "HEAR" },
	{ 1197, "HEAT" }, { 1198, "HEBE" }, { 1199, "HECK" }, { 1200, "HEED" },
	{ 1201, "HEEL" }, { 1202, "HEFT" }, { 1203, "HELD" }, { 1204, "HELL" },
	{ 1205, "HELM" }, {  206, "HEM"  }, {  207, "HEN"  }, {  208, "HER"  },
	{ 1206, "HERB" }, { 1207, "HERD" }, { 1208, "HERE" }, { 1209, "HERO" },
	{ 1210, "HERS" }, { 1211, "HESS" }, {  209, "HEW"  }, { 1212, "HEWN" },
	{  210, "HEY"  }, {  211, "HI"   }, { 1213, "HICK" }, {  212, "HID"  },
	{ 1214, "HIDE" }, { 1215, "HIGH" }, { 1216, "HIKE" }, { 1217, "HILL" },
	{ 1218, "HILT" }, {  213, "HIM"  }, { 1219, "HIND" }, { 1220, "HINT" },
	{  214, "HIP"  }, { 1221, "HIRE" }, {  215, "HIS"  }, { 1222, "HISS" },
	{  216, "HIT"  }, { 1223, "HIVE" }, {  217, "HO"   }, {  218, "HOB"  },
	{ 1224, "HOBO" }, {  219, "HOC"  }, { 1225, "HOCK" }, {  220, "HOE"  },
	{ 1226, "HOFF" }, {  221, "HOG"  }, { 1227, "HOLD" }, { 1228, "HOLE" },
	{ 1229, "HOLM" }, { 1230, "HOLT" }, { 1231, "HOME" }, { 1232, "HONE" },
	{ 1233, "HONK" }, { 1234, "HOOD" }, { 1235, "HOOF" }, { 1236, "HOOK" },
	{ 1237, "HOOT" }, {  222, "HOP"  }, { 1238, "HORN" }, { 1239, "HOSE" },
	{ 1240, "HOST" }, {  223, "HOT"  }, { 1241, "HOUR" }, { 1242, "HOVE" },
	{  224, "HOW"  }, { 1243, "HOWE" }, { 1244, "HOWL" }, { 1245, "HOYT" },
	{  225, "HUB"  }, { 1246, "HUCK" }, {  226, "HUE"  }, { 1247, "HUED" },
	{ 1248, "HUFF" }, {  227, "HUG"  }, { 1249, "HUGE" }, { 1250, "HUGH" },
	{ 1251, "HUGO" }, {  228, "HUH"  }, { 1252, "HULK" }, { 1253, "HULL" },
	{  229, "HUM"  }, { 1254, "HUNK" }, { 1255, "HUNT" }, { 1256, "HURD" },
	{ 1257, "HURL" }, { 1258, "HURT" }, { 1259, "HUSH" }, {  230, "HUT"  },
	{ 1260, "HYDE" }, { 1261, "HYMN" }, {  231, "I"    }, { 1262, "IBIS" },
	{ 1263, "ICON" }, {  232, "ICY"  }, {  233, "IDA"  }, { 1264, "IDEA" },
	{ 1265, "IDLE" }, {  234, "IF"   }, { 1266, "IFFY" }, {  235, "IKE"  },
	{  236, "ILL"  }, { 1267, "INCA" }, { 1268, "INCH" }, {  237, "INK"  },
	{  238, "INN"  }, { 1269, "INTO" }, {  239, "IO"   }, {  240, "ION"  },
	{ 1270, "IONS" }, { 1271, "IOTA" }, { 1272, "IOWA" }, {  241, "IQ"   },
	{  242, "IRA"  }, {  243, "IRE"  }, { 1273, "IRIS" }, {  244, "IRK"  },
	{ 1274, "IRMA" }, { 1275, "IRON" }, {  245, "IS"   }, { 1276, "ISLE" },
	{  246, "IT"   }, { 1277, "ITCH" }, { 1278, "ITEM" }, {  247, "ITS"  },
	{ 1279, "IVAN" }, {  248, "IVY"  }, {  249, "JAB"  }, { 1280, "JACK" },
	{ 1281, "JADE" }, {  250, "JAG"  }, { 1282, "JAIL" }, { 1283, "JAKE" },
	{  251, "JAM"  }, {  252, "JAN"  }, { 1284, "JANE" }, {  253, "JAR"  },
	{ 1285, "JAVA" }, {  254, "JAW"  }, {  255, "JAY"  }, { 1286, "JEAN" },
	{ 1287, "JEFF" }, { 1288, "JERK" }, { 1289, "JESS" }, { 1290, "JEST" },
	{  256, "JET"  }, { 1291, "JIBE" }, {  257, "JIG"  }, { 1292, "JILL" },
	{ 1293, "JILT" }, {  258, "JIM"  }, { 1294, "JIVE" }, {  259, "JO"   },
	{ 1295, "JOAN" }, {  260, "JOB"  }, { 1296, "JOBS" }, { 1297, "JOCK" },
	{  261, "JOE"  }, { 1298, "JOEL" }, { 1299, "JOEY" }, {  262, "JOG"  },
	{ 1300, "JOHN" }, { 1301, "JOIN" }, { 1302, "JOKE" }, { 1303, "JOLT" },
	{  263, "JOT"  }, { 1304, "JOVE" }, {  264, "JOY"  }, { 1305, "JUDD" },
	{ 1306, "JUDE" }, { 1307, "JUDO" }, { 1308, "JUDY" }, {  265, "JUG"  },
	{ 1309, "JUJU" }, { 1310, "JUKE" }, { 1311, "JULY" }, { 1312, "JUNE" },
	{ 1313, "JUNK" }, { 1314, "JUNO" }, { 1315, "JURY" }, { 1316, "JUST" },
	{  266, "JUT"  }, { 1317, "JUTE" }, { 1318, "KAHN" }, { 1319, "KALE" },
	{ 1320, "KANE" }, { 1321, "KANT" }, { 1322, "KARL" }, { 1323, "KATE" },
	{  267, "KAY"  }, { 1324, "KEEL" }, { 1325, "KEEN" }, {  268, "KEG"  },
	{  269, "KEN"  }, { 1326, "KENO" }, { 1327, "KENT" }, { 1328, "KERN" },
	{ 1329, "KERR" }, {  270, "KEY"  }, { 1330, "KEYS" }, { 1331, "KICK" },
	{  271, "KID"  }, { 1332, "KILL" }, {  272, "KIM"  }, {  273, "KIN"  },
	{ 1333, "KIND" }, { 1334, "KING" }, { 1335, "KIRK" }, { 1336, "KISS" },
	{  274, "KIT"  }, { 1337, "KITE" }, { 1338, "KLAN" }, { 1339, "KNEE" },
	{ 1340, "KNEW" }, { 1341, "KNIT" }, { 1342, "KNOB" }, { 1343, "KNOT" },
	{ 1344, "KNOW" }, { 1345, "KOCH" }, { 1346, "KONG" }, { 1347, "KUDO" },
	{ 1348, "KURD" }, { 1349, "KURT" }, { 1350, "KYLE" }, {  275, "LA"   },
	{  276, "LAB"  }, {  277, "LAC"  }, { 1351, "LACE" }, { 1352, "LACK" },
	{ 1353, "LACY" }, {  278, "LAD"  }, { 1354, "LADY" }, {  279, "LAG"  },
	{ 1355, "LAID" }, { 1356, "LAIN" }, { 1357, "LAIR" }, { 1358, "LAKE" },
	{  280, "LAM"  }, { 1359, "LAMB" }, { 1360, "LAME" }, { 1361, "LAND" },
	{ 1362, "LANE" }, { 1363, "LANG" }, {  281, "LAP"  }, { 1364, "LARD" },
	{ 1365, "LARK" }, { 1366, "LASS" }, { 1367, "LAST" }, { 1368, "LATE" },
	{ 1369, "LAUD" }, { 1370, "LAVA" }, {  282, "LAW"  }, { 1371, "LAWN" },
	{ 1372, "LAWS" }, {  283, "LAY"  }, { 1373, "LAYS" }, {  284, "LEA"  },
	{ 1374, "LEAD" }, { 1375, "LEAF" }, { 1376, "LEAK" }, { 1377, "LEAN" },
	{ 1378, "LEAR" }, {  285, "LED"  }, {  286, "LEE"  }, { 1379, "LEEK" },
	{ 1380, "LEER" }, { 1381, "LEFT" }, {  287, "LEG"  }, {  288, "LEN"  },
	{ 1382, "LEND" }, { 1383, "LENS" }, { 1384, "LENT" }, {  289, "LEO"  },
	{ 1385, "LEON" }, { 1386, "LESK" }, { 1387, "LESS" }, { 1388, "LEST" },
	{  290, "LET"  }, { 1389, "LETS" }, {  291, "LEW"  }, { 1390, "LIAR" },
	{ 1391, "LICE" }, { 1392, "LICK" }, {  292, "LID"  }, {  293, "LIE"  },
	{ 1393, "LIED" }, { 1394, "LIEN" }, { 1395, "LIES" }, { 1396, "LIEU" },
	{ 1397, "LIFE" }, { 1398, "LIFT" }, { 1399, "LIKE" }, { 1400, "LILA" },
	{ 1401, "LILT" }, { 1402, "LILY" }, { 1403, "LIMA" }, { 1404, "LIMB" },
	{ 1405, "LIME" }, {  294, "LIN"  }, { 1406, "LIND" }, { 1407, "LINE" },
	{ 1408, "LINK" }, { 1409, "LINT" }, { 1410, "LION" }, {  295, "LIP"  },
	{ 1411, "LISA" }, { 1412, "LIST" }, {  296, "LIT"  }, { 1413, "LIVE" },
	{  297, "LO"   }, { 1414, "LOAD" }, { 1415, "LOAF" }, { 1416, "LOAM" },
	{ 1417, "LOAN" }, {  298, "LOB"  }, { 1418, "LOCK" }, { 1419, "LOFT" },
	{  299, "LOG"  }, { 1420, "LOGE" }, { 1421, "LOIS" }, { 1422, "LOLA" },
	{ 1423, "LONE" }, { 1424, "LONG" }, { 1425, "LOOK" }, { 1426, "LOON" },
	{ 1427, "LOOT" }, {  300, "LOP"  }, { 1428, "LORD" }, { 1429, "LORE" },
	{  301, "LOS"  }, { 1430, "LOSE" }, { 1431, "LOSS" }, { 1432, "LOST" },
	{  302, "LOT"  }, {  303, "LOU"  }, { 1433, "LOUD" }, { 1434, "LOVE" },
	{  304, "LOW"  }, { 1435, "LOWE" }, {  305, "LOY"  }, { 1436, "LUCK" },
	{ 1437, "LUCY" }, {  306, "LUG"  }, { 1438, "LUGE" }, { 1439, "LUKE" },
	{ 1440, "LULU" }, { 1441, "LUND" }, { 1442, "LUNG" }, { 1443, "LURA" },
	{ 1444, "LURE" }, { 1445, "LURK" }, { 1446, "LUSH" }, { 1447, "LUST" },
	{  307, "LYE"  }, { 1448, "LYLE" }, { 1449, "LYNN" }, { 1450, "LYON" },
	{ 1451, "LYRA" }, {  308, "MA"   }, {  309, "MAC"  }, { 1452, "MACE" },
	{  310, "MAD"  }, { 1453, "MADE" }, {  311, "MAE"  }, { 1454, "MAGI" },
	{ 1455, "MAID" }, { 1456, "MAIL" }, { 1457, "MAIN" }, { 1458, "MAKE" },
	{ 1459, "MALE" }, { 1460, "MALI" }, { 1461, "MALL" }, { 1462, "MALT" },
	{  312, "MAN"  }, { 1463, "MANA" }, { 1464, "MANN" }, { 1465, "MANY" },
	{  313, "MAO"  }, {  314, "MAP"  }, { 1466, "MARC" }, { 1467, "MARE" },
	{ 1468, "MARK" }, { 1469, "MARS" }, { 1470, "MART" }, { 1471, "MARY" },
	{ 1472, "MASH" }, { 1473, "MASK" }, { 1474, "MASS" }, { 1475, "MAST" },
	{  315, "MAT"  }, { 1476, "MATE" }, { 1477, "MATH" }, { 1478, "MAUL" },
	{  316, "MAW"  }, {  317, "MAY"  }, { 1479, "MAYO" }, {  318, "ME"   },
	{ 1480, "MEAD" }, { 1481, "MEAL" }, { 1482, "MEAN" }, { 1483, "MEAT" },
	{ 1484, "MEEK" }, { 1485, "MEET" }, {  319, "MEG"  }, {  320, "MEL"  },
	{ 1486, "MELD" }, { 1487, "MELT" }, { 1488, "MEMO" }, {  321, "MEN"  },
	{ 1489, "MEND" }, { 1490, "MENU" }, { 1491, "MERT" }, { 1492, "MESH" },
	{ 1493, "MESS" }, {  322, "MET"  }, {  323, "MEW"  }, { 1494, "MICE" },
	{  324, "MID"  }, { 1495, "MIKE" }, { 1496, "MILD" }, { 1497, "MILE" },
	{ 1498, "MILK" }, { 1499, "MILL" }, { 1500, "MILT" }, { 1501, "MIMI" },
	{  325, "MIN"  }, { 1502, "MIND" }, { 1503, "MINE" }, { 1504, "MINI" },
	{ 1505, "MINK" }, { 1506, "MINT" }, { 1507, "MIRE" }, { 1508, "MISS" },
	{ 1509, "MIST" }, {  326, "MIT"  }, { 1510, "MITE" }, { 1511, "MITT" },
	{ 1512, "MOAN" }, { 1513, "MOAT" }, {  327, "MOB"  }, { 1514, "MOCK" },
	{  328, "MOD"  }, { 1515, "MODE" }, {  329, "MOE"  }, { 1516, "MOLD" },
	{ 1517, "MOLE" }, { 1518, "MOLL" }, { 1519, "MOLT" }, { 1520, "MONA" },
	{ 1521, "MONK" }, { 1522, "MONT" }, {  330, "MOO"  }, { 1523, "MOOD" },
	{ 1524, "MOON" }, { 1525, "MOOR" }, { 1526, "MOOT" }, {  331, "MOP"  },
	{ 1527, "MORE" }, { 1528, "MORN" }, { 1529, "MORT" }, {  332, "MOS"  },
	{ 1530, "MOSS" }, { 1531, "MOST" }, {  333, "MOT"  }, { 1532, "MOTH" },
	{ 1533, "MOVE" }, {  334, "MOW"  }, { 1534, "MUCH" }, { 1535, "MUCK" },
	{  335, "MUD"  }, { 1536, "MUDD" }, { 1537, "MUFF" }, {  336, "MUG"  },
	{ 1538, "MULE" }, { 1539, "MULL" }, {  337, "MUM"  }, { 1540, "MURK" },
	{ 1541, "MUSH" }, { 1542, "MUST" }, { 1543, "MUTE" }, { 1544, "MUTT" },
	{  338, "MY"   }, { 1545, "MYRA" }, { 1546, "MYTH" }, {  339, "NAB"  },
	{  340, "NAG"  }, { 1547, "NAGY" }, { 1548, "NAIL" }, { 1549, "NAIR" },
	{ 1550, "NAME" }, {  341, "NAN"  }, {  342, "NAP"  }, { 1551, "NARY" },
	{ 1552, "NASH" }, {  343, "NAT"  }, { 1553, "NAVE" }, { 1554, "NAVY" },
	{  344, "NAY"  }, {  345, "NE"   }, { 1555, "NEAL" }, { 1556, "NEAR" },
	{ 1557, "NEAT" }, { 1558, "NECK" }, {  346, "NED"  }, {  347, "NEE"  },
	{ 1559, "NEED" }, { 1560, "NEIL" }, { 1561, "NELL" }, { 1562, "NEON" },
	{ 1563, "NERO" }, { 1564, "NESS" }, { 1565, "NEST" }, {  348, "NET"  },
	{  349, "NEW"  }, { 1566, "NEWS" }, { 1567, "NEWT" }, {  350, "NIB"  },
	{ 1568, "NIBS" }, { 1569, "NICE" }, { 1570, "NICK" }, {  351, "NIL"  },
	{ 1571, "NILE" }, { 1572, "NINA" }, { 1573, "NINE" }, {  352, "NIP"  },
	{  353, "NIT"  }, {  354, "NO"   }, { 1574, "NOAH" }, {  355, "NOB"  },
	{  356, "NOD"  }, { 1575, "NODE" }, { 1576, "NOEL" }, { 1577, "NOLL" },
	{  357, "NON"  }, { 1578, "NONE" }, { 1579, "NOOK" }, { 1580, "NOON" },
	{  358, "NOR"  }, { 1581, "NORM" }, { 1582, "NOSE" }, {  359, "NOT"  },
	{ 1583, "NOTE" }, { 1584, "NOUN" }, {  360, "NOV"  }, { 1585, "NOVA" },
	{  361, "NOW"  }, {  362, "NU"   }, { 1586, "NUDE" }, { 1587, "NULL" },
	{ 1588, "NUMB" }, {  363, "NUN"  }, {  364, "NUT"  }, {  365, "O"    },
	{  366, "OAF"  }, {  367, "OAK"  }, {  368, "OAR"  }, {  369, "OAT"  },
	{ 1589, "OATH" }, { 1590, "OBEY" }, { 1591, "OBOE" }, {  370, "ODD"  },
	{  371, "ODE"  }, { 1592, "ODIN" }, {  372, "OF"   }, {  373, "OFF"  },
	{  374, "OFT"  }, {  375, "OH"   }, { 1593, "OHIO" }, {  376, "OIL"  },
	{ 1594, "OILY" }, { 1595, "OINT" }, {  377, "OK"   }, { 1596, "OKAY" },
	{ 1597, "OLAF" }, {  378, "OLD"  }, { 1598, "OLDY" }, { 1599, "OLGA" },
	{ 1600, "OLIN" }, { 1601, "OMAN" }, { 1602, "OMEN" }, { 1603, "OMIT" },
	{  379, "ON"   }, { 1604, "ONCE" }, {  380, "ONE"  }, { 1605, "ONES" },
	{ 1606, "ONLY" }, { 1607, "ONTO" }, { 1608, "ONUS" }, {  381, "OR"   },
	{ 1609, "ORAL" }, {  382, "ORB"  }, {  383, "ORE"  }, { 1610, "ORGY" },
	{  384, "ORR"  }, {  385, "OS"   }, { 1611, "OSLO" }, { 1612, "OTIS" },
	{  386, "OTT"  }, { 1613, "OTTO" }, { 1614, "OUCH" }, {  387, "OUR"  },
	{ 1615, "OUST" }, {  388, "OUT"  }, { 1616, "OUTS" }, {  389, "OVA"  },
	{ 1617, "OVAL" }, { 1618, "OVEN" }, { 1619, "OVER" }, {  390, "OW"   },
	{  391, "OWE"  }, {  392, "OWL"  }, { 1620, "OWLY" }, {  393, "OWN"  },
	{ 1621, "OWNS" }, {  394, "OX"   }, {  395, "PA"   }, {  396, "PAD"  },
	{  397, "PAL"  }, {  398, "PAM"  }, {  399, "PAN"  }, {  400, "PAP"  },
	{  401, "PAR"  }, {  402, "PAT"  }, {  403, "PAW"  }, {  404, "PAY"  },
	{  405, "PEA"  }, {  406, "PEG"  }, {  407, "PEN"  }, {  408, "PEP"  },
	{  409, "PER"  }, {  410, "PET"  }, {  411, "PEW"  }, {  412, "PHI"  },
	{  413, "PI"   }, {  414, "PIE"  }, {  415, "PIN"  }, {  416, "PIT"  },
	{  417, "PLY"  }, {  418, "PO"   }, {  419, "POD"  }, {  420, "POE"  },
	{  421, "POP"  }, {  422, "POT"  }, {  423, "POW"  }, {  424, "PRO"  },
	{  425, "PRY"  }, {  426, "PUB"  }, {  427, "PUG"  }, {  428, "PUN"  },
	{  429, "PUP"  }, {  430, "PUT"  }, { 1622, "QUAD" }, { 1623, "QUIT" },
	{  431, "QUO"  }, { 1624, "QUOD" }, { 1625, "RACE" }, { 1626, "RACK" },
	{ 1627, "RACY" }, { 1628, "RAFT" }, {  432, "RAG"  }, { 1629, "RAGE" },
	{ 1630, "RAID" }, { 1631, "RAIL" }, { 1632, "RAIN" }, { 1633, "RAKE" },
	{  433, "RAM"  }, {  434, "RAN"  }, { 1634, "RANK" }, { 1635, "RANT" },
	{  435, "RAP"  }, { 1636, "RARE" }, { 1637, "RASH" }, {  436, "RAT"  },
	{ 1638, "RATE" }, { 1639, "RAVE" }, {  437, "RAW"  }, {  438, "RAY"  },
	{ 1640, "RAYS" }, { 1641, "READ" }, { 1642, "REAL" }, { 1643, "REAM" },
	{ 1644, "REAR" }, {  439, "REB"  }, { 1645, "RECK" }, {  440, "RED"  },
	{ 1646, "REED" }, { 1647, "REEF" }, { 1648, "REEK" }, { 1649, "REEL" },
	{ 1650, "REID" }, { 1651, "REIN" }, { 1652, "RENA" }, { 1653, "REND" },
	{ 1654, "RENT" }, {  441, "REP"  }, { 1655, "REST" }, {  442, "RET"  },
	{  443, "RIB"  }, { 1656, "RICE" }, { 1657, "RICH" }, { 1658, "RICK" },
	{  444, "RID"  }, { 1659, "RIDE" }, { 1660, "RIFT" }, {  445, "RIG"  },
	{ 1661, "RILL" }, {  446, "RIM"  }, { 1662, "RIME" }, { 1663, "RING" },
	{ 1664, "RINK" }, {  447, "RIO"  }, {  448, "RIP"  }, { 1665, "RISE" },
	{ 1666, "RISK" }, { 1667, "RITE" }, { 1668, "ROAD" }, { 1669, "ROAM" },
	{ 1670, "ROAR" }, {  449, "ROB"  }, { 1671, "ROBE" }, { 1672, "ROCK" },
	{  450, "ROD"  }, { 1673, "RODE" }, {  451, "ROE"  }, { 1674, "ROIL" },
	{ 1675, "ROLL" }, { 1676, "ROME" }, {  452, "RON"  }, { 1677, "ROOD" },
	{ 1678, "ROOF" }, { 1679, "ROOK" }, { 1680, "ROOM" }, { 1681, "ROOT" },
	{ 1682, "ROSA" }, { 1683, "ROSE" }, { 1684, "ROSS" }, { 1685, "ROSY" },
	{  453, "ROT"  }, { 1686, "ROTH" }, { 1687, "ROUT" }, { 1688, "ROVE" },
	{  454, "ROW"  }, { 1689, "ROWE" }, { 1690, "ROWS" }, {  455, "ROY"  },
	{  456, "RUB"  }, { 1691, "RUBE" }, { 1692, "RUBY" }, { 1693, "RUDE" },
	{ 1694, "RUDY" }, {  457, "RUE"  }, {  458, "RUG"  }, { 1695, "RUIN" },
	{ 1696, "RULE" }, {  459, "RUM"  }, {  460, "RUN"  }, { 1697, "RUNG" },
	{ 1698, "RUNS" }, { 1699, "RUNT" }, { 1700, "RUSE" }, { 1701, "RUSH" },
	{ 1702, "RUSK" }, { 1703, "RUSS" }, { 1704, "RUST" }, { 1705, "RUTH" },
	{  461, "RYE"  }, {  462, "SAC"  }, { 1706, "SACK" }, {  463, "SAD"  },
	{ 1707, "SAFE" }, {  464, "SAG"  }, { 1708, "SAGE" }, { 1709, "SAID" },
	{ 1710, "SAIL" }, {  465, "SAL"  }, { 1711, "SALE" }, { 1712, "SALK" },
	{ 1713, "SALT" }, {  466, "SAM"  }, { 1714, "SAME" }, {  467, "SAN"  },
	{ 1715, "SAND" }, { 1716, "SANE" }, { 1717, "SANG" }, { 1718, "SANK" },
	{  468, "SAP"  }, { 1719, "SARA" }, {  469, "SAT"  }, { 1720, "SAUL" },
	{ 1721, "SAVE" }, {  470, "SAW"  }, {  471, "SAY"  }, { 1722, "SAYS" },
	{ 1723, "SCAN" }, { 1724, "SCAR" }, { 1725, "SCAT" }, { 1726, "SCOT" },
	{  472, "SEA"  }, { 1727, "SEAL" }, { 1728, "SEAM" }, { 1729, "SEAR" },
	{ 1730, "SEAT" }, {  473, "SEC"  }, {  474, "SEE"  }, { 1731, "SEED" },
	{ 1732, "SEEK" }, { 1733, "SEEM" }, { 1734, "SEEN" }, { 1735, "SEES" },
	{ 1736, "SELF" }, { 1737, "SELL" }, {  475, "SEN"  }, { 1738, "SEND" },
	{ 1739, "SENT" }, {  476, "SET"  }, { 1740, "SETS" }, {  477, "SEW"  },
	{ 1741, "SEWN" }, { 1742, "SHAG" }, { 1743, "SHAM" }, { 1744, "SHAW" },
	{ 1745, "SHAY" }, {  478, "SHE"  }, { 1746, "SHED" }, { 1747, "SHIM" },
	{ 1748, "SHIN" }, { 1749, "SHOD" }, { 1750, "SHOE" }, { 1751, "SHOT" },
	{ 1752, "SHOW" }, { 1753, "SHUN" }, { 1754, "SHUT" }, {  479, "SHY"  },
	{ 1755, "SICK" }, { 1756, "SIDE" }, { 1757, "SIFT" }, { 1758, "SIGH" },
	{ 1759, "SIGN" }, { 1760, "SILK" }, { 1761, "SILL" }, { 1762, "SILO" },
	{ 1763, "SILT" }, {  480, "SIN"  }, { 1764, "SINE" }, { 1765, "SING" },
	{ 1766, "SINK" }, {  481, "SIP"  }, {  482, "SIR"  }, { 1767, "SIRE" },
	{  483, "SIS"  }, {  484, "SIT"  }, { 1768, "SITE" }, { 1769, "SITS" },
	{ 1770, "SITU" }, { 1771, "SKAT" }, { 1772, "SKEW" }, {  485, "SKI"  },
	{ 1773, "SKID" }, { 1774, "SKIM" }, { 1775, "SKIN" }, { 1776, "SKIT" },
	{  486, "SKY"  }, { 1777, "SLAB" }, { 1778, "SLAM" }, { 1779, "SLAT" },
	{ 1780, "SLAY" }, { 1781, "SLED" }, { 1782, "SLEW" }, { 1783, "SLID" },
	{ 1784, "SLIM" }, { 1785, "SLIT" }, { 1786, "SLOB" }, { 1787, "SLOG" },
	{ 1788, "SLOT" }, { 1789, "SLOW" }, { 1790, "SLUG" }, { 1791, "SLUM" },
	{ 1792, "SLUR" }, {  487, "SLY"  }, { 1793, "SMOG" }, { 1794, "SMUG" },
	{ 1795, "SNAG" }, { 1796, "SNOB" }, { 1797, "SNOW" }, { 1798, "SNUB" },
	{ 1799, "SNUG" }, {  488, "SO"   }, { 1800, "SOAK" }, { 1801, "SOAR" },
	{  489, "SOB"  }, { 1802, "SOCK" }, {  490, "SOD"  }, { 1803, "SODA" },
	{ 1804, "SOFA" }, { 1805, "SOFT" }, { 1806, "SOIL" }, { 1807, "SOLD" },
	{ 1808, "SOME" }, {  491, "SON"  }, { 1809, "SONG" }, { 1810, "SOON" },
	{ 1811, "SOOT" }, {  492, "SOP"  }, { 1812, "SORE" }, { 1813, "SORT" },
	{ 1814, "SOUL" }, { 1815, "SOUR" }, {  493, "SOW"  }, { 1816, "SOWN" },
	{  494, "SOY"  }, {  495, "SPA"  }, {  496, "SPY"  }, { 1817, "STAB" },
	{ 1818, "STAG" }, { 1819, "STAN" }, { 1820, "STAR" }, { 1821, "STAY" },
	{ 1822, "STEM" }, { 1823, "STEW" }, { 1824, "STIR" }, { 1825, "STOW" },
	{ 1826, "STUB" }, { 1827, "STUN" }, {  497, "SUB"  }, { 1828, "SUCH" },
	{  498, "SUD"  }, { 1829, "SUDS" }, {  499, "SUE"  }, { 1830, "SUIT" },
	{ 1831, "SULK" }, {  500, "SUM"  }, { 1832, "SUMS" }, {  501, "SUN"  },
	{ 1833, "SUNG" }, { 1834, "SUNK" }, {  502, "SUP"  }, { 1835, "SURE" },
	{ 1836, "SURF" }, { 1837, "SWAB" }, { 1838, "SWAG" }, { 1839, "SWAM" },
	{ 1840, "SWAN" }, { 1841, "SWAT" }, { 1842, "SWAY" }, { 1843, "SWIM" },
	{ 1844, "SWUM" }, {  503, "TAB"  }, { 1845, "TACK" }, { 1846, "TACT" },
	{  504, "TAD"  }, {  505, "TAG"  }, { 1847, "TAIL" }, { 1848, "TAKE" },
	{ 1849, "TALE" }, { 1850, "TALK" }, { 1851, "TALL" }, {  506, "TAN"  },
	{ 1852, "TANK" }, {  507, "TAP"  }, {  508, "TAR"  }, { 1853, "TASK" },
	{ 1854, "TATE" }, { 1855, "TAUT" }, {  509, "TEA"  }, { 1856, "TEAL" },
	{ 1857, "TEAM" }, { 1858, "TEAR" }, { 1859, "TECH" }, {  510, "TED"  },
	{  511, "TEE"  }, { 1860, "TEEM" }, { 1861, "TEEN" }, { 1862, "TEET" },
	{ 1863, "TELL" }, {  512, "TEN"  }, { 1864, "TEND" }, { 1865, "TENT" },
	{ 1866, "TERM" }, { 1867, "TERN" }, { 1868, "TESS" }, { 1869, "TEST" },
	{ 1870, "THAN" }, { 1871, "THAT" }, {  513, "THE"  }, { 1872, "THEE" },
	{ 1873, "THEM" }, { 1874, "THEN" }, { 1875, "THEY" }, { 1876, "THIN" },
	{ 1877, "THIS" }, { 1878, "THUD" }, { 1879, "THUG" }, {  514, "THY"  },
	{  515, "TIC"  }, { 1880, "TICK" }, { 1881, "TIDE" }, { 1882, "TIDY" },
	{  516, "TIE"  }, { 1883, "TIED" }, { 1884, "TIER" }, { 1885, "TILE" },
	{ 1886, "TILL" }, { 1887, "TILT" }, {  517, "TIM"  }, { 1888, "TIME" },
	{  518, "TIN"  }, { 1889, "TINA" }, { 1890, "TINE" }, { 1891, "TINT" },
	{ 1892, "TINY" }, {  519, "TIP"  }, { 1893, "TIRE" }, {  520, "TO"   },
	{ 1894, "TOAD" }, {  521, "TOE"  }, {  522, "TOG"  }, { 1895, "TOGO" },
	{ 1896, "TOIL" }, { 1897, "TOLD" }, { 1898, "TOLL" }, {  523, "TOM"  },
	{  524, "TON"  }, { 1899, "TONE" }, { 1900, "TONG" }, { 1901, "TONY" },
	{  525, "TOO"  }, { 1902, "TOOK" }, { 1903, "TOOL" }, { 1904, "TOOT" },
	{  526, "TOP"  }, { 1905, "TORE" }, { 1906, "TORN" }, { 1907, "TOTE" },
	{ 1908, "TOUR" }, { 1909, "TOUT" }, {  527, "TOW"  }, { 1910, "TOWN" },
	{  528, "TOY"  }, { 1911, "TRAG" }, { 1912, "TRAM" }, { 1913, "TRAY" },
	{ 1914, "TREE" }, { 1915, "TREK" }, { 1916, "TRIG" }, { 1917, "TRIM" },
	{ 1918, "TRIO" }, { 1919, "TROD" }, { 1920, "TROT" }, { 1921, "TROY" },
	{ 1922, "TRUE" }, {  529, "TRY"  }, {  530, "TUB"  }, { 1923, "TUBA" },
	{ 1924, "TUBE" }, { 1925, "TUCK" }, { 1926, "TUFT" }, {  531, "TUG"  },
	{  532, "TUM"  }, {  533, "TUN"  }, { 1927, "TUNA" }, { 1928, "TUNE" },
	{ 1929, "TUNG" }, { 1930, "TURF" }, { 1931, "TURN" }, { 1932, "TUSK" },
	{ 1933, "TWIG" }, { 1934, "TWIN" }, { 1935, "TWIT" }, {  534, "TWO"  },
	{ 1936, "ULAN" }, {  535, "UN"   }, { 1937, "UNIT" }, {  536, "UP"   },
	{ 1938, "URGE" }, {  537, "US"   }, {  538, "USE"  }, { 1939, "USED" },
	{ 1940, "USER" }, { 1941, "USES" }, { 1942, "UTAH" }, { 1943, "VAIL" },
	{ 1944, "VAIN" }, { 1945, "VALE" }, {  539, "VAN"  }, { 1946, "VARY" },
	{ 1947, "VASE" }, { 1948, "VAST" }, {  540, "VAT"  }, { 1949, "VEAL" },
	{ 1950, "VEDA" }, { 1951, "VEIL" }, { 1952, "VEIN" }, { 1953, "VEND" },
	{ 1954, "VENT" }, { 1955, "VERB" }, { 1956, "VERY" }, {  541, "VET"  },
	{ 1957, "VETO" }, { 1958, "VICE" }, {  542, "VIE"  }, { 1959, "VIEW" },
	{ 1960, "VINE" }, { 1961, "VISE" }, { 1962, "VOID" }, { 1963, "VOLT" },
	{ 1964, "VOTE" }, { 1965, "WACK" }, {  543, "WAD"  }, { 1966, "WADE" },
	{  544, "WAG"  }, { 1967, "WAGE" }, { 1968, "WAIL" }, { 1969, "WAIT" },
	{ 1970, "WAKE" }, { 1971, "WALE" }, { 1972, "WALK" }, { 1973, "WALL" },
	{ 1974, "WALT" }, { 1975, "WAND" }, { 1976, "WANE" }, { 1977, "WANG" },
	{ 1978, "WANT" }, {  545, "WAR"  }, { 1979, "WARD" }, { 1980, "WARM" },
	{ 1981, "WARN" }, { 1982, "WART" }, {  546, "WAS"  }, { 1983, "WASH" },
	{ 1984, "WAST" }, { 1985, "WATS" }, { 1986, "WATT" }, { 1987, "WAVE" },
	{ 1988, "WAVY" }, {  547, "WAY"  }, { 1989, "WAYS" }, {  548, "WE"   },
	{ 1990, "WEAK" }, { 1991, "WEAL" }, { 1992, "WEAN" }, { 1993, "WEAR" },
	{  549, "WEB"  }, {  550, "WED"  }, {  551, "WEE"  }, { 1994, "WEED" },
	{ 1995, "WEEK" }, { 1996, "WEIR" }, { 1997, "WELD" }, { 1998, "WELL" },
	{ 1999, "WELT" }, { 2000, "WENT" }, { 2001, "WERE" }, { 2002, "WERT" },
	{ 2003, "WEST" }, {  552, "WET"  }, { 2004, "WHAM" }, { 2005, "WHAT" },
	{ 2006, "WHEE" }, { 2007, "WHEN" }, { 2008, "WHET" }, {  553, "WHO"  },
	{ 2009, "WHOA" }, { 2010, "WHOM" }, {  554, "WHY"  }, { 2011, "WICK" },
	{ 2012, "WIFE" }, { 2013, "WILD" }, { 2014, "WILL" }, {  555, "WIN"  },
	{ 2015, "WIND" }, { 2016, "WINE" }, { 2017, "WING" }, { 2018, "WINK" },
	{ 2019, "WINO" }, { 2020, "WIRE" }, { 2021, "WISE" }, { 2022, "WISH" },
	{  556, "WIT"  }, { 2023, "WITH" }, {  557, "WOK"  }, { 2024, "WOLF" },
	{  558, "WON"  }, { 2025, "WONT" }, {  559, "WOO"  }, { 2026, "WOOD" },
	{ 2027, "WOOL" }, { 2028, "WORD" }, { 2029, "WORE" }, { 2030, "WORK" },
	{ 2031, "WORM" }, { 2032, "WORN" }, { 2033, "WOVE" }, {  560, "WOW"  },
	{ 2034, "WRIT" }, {  561, "WRY"  }, {  562, "WU"   }, { 2035, "WYNN" },
	{ 2036, "YALE" }, {  563, "YAM"  }, { 2037, "YANG" }, { 2038, "YANK" },
	{  564, "YAP"  }, { 2039, "YARD" }, { 2040, "YARN" }, {  565, "YAW"  },
	{ 2041, "YAWL" }, { 2042, "YAWN" }, {  566, "YE"   }, {  567, "YEA"  },
	{ 2043, "YEAH" }, { 2044, "YEAR" }, { 2045, "YELL" }, {  568, "YES"  },
	{  569, "YET"  }, { 2046, "YOGA" }, { 2047, "YOKE" }, {  570, "YOU"  },
};

int otp_lookup_word(const char *word)
{
	int l, u, idx, c;
	int first = *word - 'A';

	if ((first < 0) || (first > 'Y' - 'A'))
		return -1;

	l = hints[first].l;
	u = hints[first].u;
	while (l < u) {
		idx = (l + u) / 2;
		c = strncmp(word, dictionary[idx].word, 4);

		if (c < 0)
			u = idx;
		else if (c > 0)
			l = idx + 1;
		else
			return dictionary[idx].value;
	}

	return -1;
}