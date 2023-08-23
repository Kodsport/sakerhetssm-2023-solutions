from Crypto.Util import number

def cubesearch(n):
	start = 0
	end = n

	while True:
		if abs(start - end) == 1:
			return end

		mid = (start + end) // 2
		error = abs(n - mid * mid * mid)

		if mid * mid * mid > n:
			end = mid
		else:
			start = mid

e = 3
n = 26216069855582688681664919208732341483332945557603575586164177922626866691728789637902060259143688013995539475318748319209855287609241203728948935195849219141510974157730734393731592115097644183808793896944480553245382039791152173046604610869171721730109243423352612217245920004912478370249893939677538797898781930668529595026163009670059336790935337183484982297834500418312664566324818703237484578005559640952835661325070859351506616760689545986269840467046268207561608993356812381677695111046119845441134106334943920788329856311817985896072003923450567866692885900282314001538581497600385176592279132665481044043579
c = 37512613776920114237307065750966107352773589153931564204301861476079215858919341207754476440317090250964041603532325146258362418321188362914048596823931787980509689115033654189202593872625260089520904439393947577746258047870835771650650091256724914578789246836454331003042667734023950748530026900657845774627850884761459783452520457900267166359077199039268032608245444490054919825322402291069380777189584383996090250955741100913496979130342158035105928464819169421545078471526214569622871417389392242716121835589615337856194635938320171155544237941716616918014464267963026958278117381908943063335134145099771238363335466188685993270498767641610023911471858154979938120041502208257874447219247393318763474195459680265848218379151279612737849210792735673144197621275652021646944252947557041006323

print(b"SSM{m1n_m1n1_m1n1r4kn4r3}")
print(number.long_to_bytes(cubesearch((c//n) * 100)))