q = 21888242871839275222246405745257275088696311157297823662689037894645226208583  # BN curve group order
Fq = GF(q)

# Define the quadratic extension field
K2.<x> = PolynomialRing(Fq)
Fq2.<u> = Fq.extension(x^2+1)  # Quadratic extension with i^2 = -1

# Define the G2 curve parameters
a1 = 0
a2 = 0
a3 = 0
b2 = 3 / (u + 9)  # Twisted curve parameter
E2 = EllipticCurve(Fq2, [0, b2])  # y^2 = x^3 + b2

# Create symbolic variables for a generic point on G2
R.<x1,y1,x2,y2> = PolynomialRing(Fq2, 4)

def validate_double_and_add():
    if True:
        # λ₁ = (y₂ - y₁)/(x₂ - x₁)
        lambda_1 = (y2-y1)/(x2-x1)

        # x₃ = λ₁(λ₁ + a₁) - a₂ - x₁ - x₂
        x3 = lambda_1*(lambda_1+a1) - a2 - x1 - x2

        # λ₂ = (a₁x₃ + a₃ + 2y₁)/(x₁ - x₃) - λ₁
        lambda_2 = (a1*x3+a3+2*y1)/(x1 - x3) - lambda_1

        # x₄ = λ₂(λ₂ + a₁) - a₂ - x₁ - x₃
        new_x_canonical = lambda_2*(lambda_2+a1) - a2 - x1 - x3
        # y₄ = λ₂(x₁ - x₄) - a₁x₄ - a₃ - y₁
        new_y_canonical = lambda_2*(x1 - new_x_canonical) - a1*new_x_canonical- a3 - y1
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

        # let mut new_x_minus_this_x = new_x.sub(cs, &mut self.x);
        new_x_minus_this_x = new_x - x1

        # let mut two_y = self.y.double(cs);
        two_y = y1 * 2

        # let mut t0 = two_y.div(cs, &mut new_x_minus_this_x);
        t0 = two_y / new_x_minus_this_x

        # let mut t1 = lambda.add(cs, &mut t0);
        t1 = lambda_impl + t0

        # let mut new_x_plus_this_x = new_x.add(cs, &mut self.x);
        new_x_plus_this_x = new_x + x1

        # let mut new_x = t1.square(cs);
        new_x = t1^2

        # new_x = new_x.sub(cs, &mut new_x_plus_this_x);
        new_x = new_x - new_x_plus_this_x

        # let mut new_x_minus_x = new_x.sub(cs, &mut self.x);
        new_x_minus_x = new_x - x1

        # let mut new_y = t1.mul(cs, &mut new_x_minus_x);
        new_y = t1 * new_x_minus_x

        # new_y = new_y.sub(cs, &mut self.y);
        new_y = new_y - y1

    # Verify the implementations match
    assert(bool(new_x_canonical == new_x))
    assert(bool(new_y_canonical == new_y))
    print('double-and-add ok')

validate_double_and_add()
