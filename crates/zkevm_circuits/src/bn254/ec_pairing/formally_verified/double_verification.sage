q = 21888242871839275222246405745257275088696311157297823662689037894645226208583
Fq = GF(q)

K2.<x> = PolynomialRing(Fq)
Fq2.<u> = Fq.extension(x^2+1)

a = 0
b = 3 / (u + 9)
E = EllipticCurve(Fq2, [0, b])

R.<x1,y1> = PolynomialRing(Fq2, 2)

def validate_double():
    # https://www.hyperelliptic.org/EFD/g1p/data/shortw/coordinates
    # doubling x = (3 x1^2+a)^2/(2 y1)^2-x1-x1
    # doubling y = (2 x1+x1) (3 x1^2+a)/(2 y1)-(3 x1^2+a)^3/(2 y1)^3-y1
    if True:
        new_x_canonical = (3*x1^2+a)^2/(2*y1)^2-x1-x1
        new_y_canonical = (2*x1+x1)*(3*x1^2+a)/(2*y1)-(3*x1^2+a)^3/(2*y1)^3-y1

    # alternative_pairing.rs TwistedCurvePoint<F>::double<CS: ConstraintSystem<F>>(&mut self, cs: &mut CS) 
    if True:
        # let mut x_squared = self.x.square(cs);
        x_squared = x1^2

        # let mut x_squared_3 = x_squared.double(cs);
        x_squared_3 = x_squared * 2

        # x_squared_3 = x_squared_3.add(cs, &mut x_squared);
        x_squared_3 = x_squared_3 + x_squared

        # let mut two_y = self.y.double(cs);
        two_y = 2 * y1

        # let mut lambda = x_squared_3.div(cs, &mut two_y);
        lambda_impl = x_squared_3 / two_y

        # let mut lambda_squared = lambda.square(cs);
        lambda_squared = lambda_impl^2

        # let mut two_x = self.x.double(cs);
        two_x = 2 * x1
            
        # let mut new_x = lambda_squared.sub(cs, &mut two_x);
        new_x = lambda_squared - two_x
        
        # let mut x_minus_new_x = self.x.sub(cs, &mut new_x);
        x_minus_new_x = x1 - new_x
            
        # let mut new_y = x_minus_new_x.mul(cs, &mut lambda);
        new_y = x_minus_new_x * lambda_impl

        # new_y = new_y.sub(cs, &mut self.y);
        new_y = new_y - y1

    assert(bool(new_x_canonical == new_x))
    assert(bool(new_y_canonical == new_y))
    print('double ok')
validate_double()
