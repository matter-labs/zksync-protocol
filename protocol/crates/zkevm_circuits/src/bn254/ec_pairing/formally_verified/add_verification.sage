q = 21888242871839275222246405745257275088696311157297823662689037894645226208583
Fq = GF(q)

K2.<x> = PolynomialRing(Fq)
Fq2.<u> = Fq.extension(x^2+1)

b = 3 / (u + 9)
E = EllipticCurve(Fq2, [0, b])

R.<x1,y1,x2,y2> = PolynomialRing(Fq2, 4)

def validate_add():
    if True:
        # https://www.hyperelliptic.org/EFD/g1p/data/shortw/coordinates
        # addition x = (y2-y1)^2/(x2-x1)^2-x1-x2
        # addition y = (2 x1+x2) (y2-y1)/(x2-x1)-(y2-y1)^3/(x2-x1)^3-y1
        new_x_canonical = (y2-y1)^2/(x2-x1)^2-x1-x2
        new_y_canonical = (2*x1+x2)*(y2-y1)/(x2-x1)-(y2-y1)^3/(x2-x1)^3-y1
    
    if True:
        # let mut other_x_minus_this_x = other.x.sub(cs, &mut self.x);
        other_x_minus_this_x = x2 - x1

        # let mut other_y_minus_this_y = other.y.sub(cs, &mut self.y);
        other_y_minus_this_y = y2 - y1

        # let mut lambda = other_y_minus_this_y.div(cs, &mut other_x_minus_this_x);
        lambda_impl = other_y_minus_this_y / other_x_minus_this_x

        # let mut lambda_squared = lambda.square(cs);
        lambda_squared = lambda_impl^2

        # let mut other_x_plus_this_x = other.x.add(cs, &mut self.x);
        other_x_plus_this_x = x2 + x1

        # let mut new_x = lambda_squared.sub(cs, &mut other_x_plus_this_x);
        new_x = lambda_squared - other_x_plus_this_x

        # let mut this_x_minus_new_x = self.x.sub(cs, &mut new_x);
        this_x_minus_new_x = x1 - new_x

        # let mut new_y = lambda.mul(cs, &mut this_x_minus_new_x);
        new_y = lambda_impl * this_x_minus_new_x

        # new_y = new_y.sub(cs, &mut self.y);
        new_y = new_y - y1

    # Verify the implementations match
    assert(bool(new_x_canonical == new_x))
    assert(bool(new_y_canonical == new_y))
    print('add ok')
validate_add()
