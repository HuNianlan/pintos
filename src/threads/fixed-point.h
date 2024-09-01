#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

typedef int fp;


#define p 17
#define q 14

// #define f (1 << q)

#define fp_convert(n) ((fp)(n << q))

#define fp_convert_to_i_zero(x) (x >> q)

#define fp_convert_to_i_nearest(x) (x >= 0 ? ((x + (1 << (q-1))) >> q):((x - (1 << (q-1))) >> q)) 

#define fp_add(x,y) (x + y)

#define fp_sub(x,y) (x - y)

#define fp_add_i(x,n) (x + (n << q))

#define fp_sub_i(x,n) (x - (n << q))

#define fp_mult(x,y) ((((int64_t) x) * y >> q))

#define fp_mult_i(x,n) (x*n)

#define fp_div(x,y) ((fp)((((int64_t) x) << q) / y))

#define fp_div_i(x,n) (x / n)



// #define FP_ROUND(A) (A >= 0 ? ((x + (1 << (q - 1))) >> q) \
//         : ((A - (1 << (FP_SHIFT_AMOUNT - 1))) >> FP_SHIFT_AMOUNT))

#endif /* thread/fixed-point.h */