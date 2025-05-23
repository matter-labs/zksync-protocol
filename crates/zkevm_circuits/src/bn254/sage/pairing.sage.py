

# This file was *autogenerated* from the file pairing.sage
from sage.all_cmdline import *   # import sage library

_sage_const_4965661367192848881 = Integer(4965661367192848881); _sage_const_6 = Integer(6); _sage_const_2 = Integer(2); _sage_const_0 = Integer(0); _sage_const_1 = Integer(1); _sage_const_4 = Integer(4); _sage_const_13 = Integer(13)# Curve parameter u and the value of [log2(6x+2)] - 1:
u = _sage_const_4965661367192848881 
six_u_plus_2 = _sage_const_6 *u+_sage_const_2 

six_u_plus_2_naf = [
    _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_1 , _sage_const_0 , -_sage_const_1 ,
    _sage_const_0 , _sage_const_0 , _sage_const_1 , -_sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 ,
    _sage_const_0 , _sage_const_1 , _sage_const_1 , _sage_const_0 , -_sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , 
    _sage_const_0 , -_sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_1 ,
    _sage_const_1 , _sage_const_0 , _sage_const_0 , -_sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , 
    _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_0 , -_sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 ,
    _sage_const_1 , _sage_const_0 , _sage_const_0 , -_sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_0 , _sage_const_1 , 
    _sage_const_1 , _sage_const_0 , -_sage_const_1 , _sage_const_0 , _sage_const_0 , _sage_const_1 , _sage_const_0 , _sage_const_1 , 
    _sage_const_1 ]
print('\nCurve in WNAF format: {}', six_u_plus_2_naf)

# Verifying that the decomposition is indeed correct:
six_u_plus_2_wnaf = sum([k_i * _sage_const_2 **i for i, k_i in enumerate(six_u_plus_2_naf)])
assert six_u_plus_2_wnaf == six_u_plus_2

def to_wnaf(k: Integer) -> list[Integer]:
    """
    Converts an integer to its WNAF representation.
    """

    k = Integer(k)
    k_wnaf = []
    while k > _sage_const_0 :
        if k % _sage_const_2  == _sage_const_1 :
            k_i = _sage_const_2  - (k % _sage_const_4 )
            k -= k_i
        else:
            k_i = _sage_const_0 
        k //= _sage_const_2 
        k_wnaf.append(k_i)
    return k_wnaf

print('\nWNAF representation of 4: {}', to_wnaf(_sage_const_4 ))
print('\nWNAF representation of 13: {}', to_wnaf(_sage_const_13 ))
print('\nWNAF representation of u: {}', to_wnaf(u))

