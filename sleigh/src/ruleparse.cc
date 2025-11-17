/* A Bison parser, made by GNU Bison 3.8.2.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2021 Free Software Foundation,
   Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output, and Bison version.  */
#define YYBISON 30802

/* Bison version string.  */
#define YYBISON_VERSION "3.8.2"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1


/* Substitute the variable and function names.  */
#define yyparse         ruleparseparse
#define yylex           ruleparselex
#define yyerror         ruleparseerror
#define yydebug         ruleparsedebug
#define yynerrs         ruleparsenerrs
#define yylval          ruleparselval
#define yychar          ruleparsechar

/* First part of user prologue.  */
#line 16 "src/ruleparse.y"

#ifdef CPUI_RULECOMPILE
#include "rulecompile.hh"

#define YYERROR_VERBOSE

extern RuleCompile *rulecompile;
extern int ruleparselex(void);
extern int ruleparseerror(const char *str);


#line 90 "src/ruleparse.cc"

# ifndef YY_CAST
#  ifdef __cplusplus
#   define YY_CAST(Type, Val) static_cast<Type> (Val)
#   define YY_REINTERPRET_CAST(Type, Val) reinterpret_cast<Type> (Val)
#  else
#   define YY_CAST(Type, Val) ((Type) (Val))
#   define YY_REINTERPRET_CAST(Type, Val) ((Type) (Val))
#  endif
# endif
# ifndef YY_NULLPTR
#  if defined __cplusplus
#   if 201103L <= __cplusplus
#    define YY_NULLPTR nullptr
#   else
#    define YY_NULLPTR 0
#   endif
#  else
#   define YY_NULLPTR ((void*)0)
#  endif
# endif

#include "ruleparse.hh"
/* Symbol kind.  */
enum yysymbol_kind_t
{
  YYSYMBOL_YYEMPTY = -2,
  YYSYMBOL_YYEOF = 0,                      /* "end of file"  */
  YYSYMBOL_YYerror = 1,                    /* error  */
  YYSYMBOL_YYUNDEF = 2,                    /* "invalid token"  */
  YYSYMBOL_RIGHT_ARROW = 3,                /* RIGHT_ARROW  */
  YYSYMBOL_LEFT_ARROW = 4,                 /* LEFT_ARROW  */
  YYSYMBOL_DOUBLE_RIGHT_ARROW = 5,         /* DOUBLE_RIGHT_ARROW  */
  YYSYMBOL_DOUBLE_LEFT_ARROW = 6,          /* DOUBLE_LEFT_ARROW  */
  YYSYMBOL_OP_BOOL_OR = 7,                 /* OP_BOOL_OR  */
  YYSYMBOL_OP_BOOL_AND = 8,                /* OP_BOOL_AND  */
  YYSYMBOL_OP_BOOL_XOR = 9,                /* OP_BOOL_XOR  */
  YYSYMBOL_OP_INT_OR = 10,                 /* OP_INT_OR  */
  YYSYMBOL_OP_INT_XOR = 11,                /* OP_INT_XOR  */
  YYSYMBOL_OP_INT_AND = 12,                /* OP_INT_AND  */
  YYSYMBOL_OP_INT_EQUAL = 13,              /* OP_INT_EQUAL  */
  YYSYMBOL_OP_INT_NOTEQUAL = 14,           /* OP_INT_NOTEQUAL  */
  YYSYMBOL_OP_FLOAT_EQUAL = 15,            /* OP_FLOAT_EQUAL  */
  YYSYMBOL_OP_FLOAT_NOTEQUAL = 16,         /* OP_FLOAT_NOTEQUAL  */
  YYSYMBOL_OP_INT_LESS = 17,               /* OP_INT_LESS  */
  YYSYMBOL_OP_INT_LESSEQUAL = 18,          /* OP_INT_LESSEQUAL  */
  YYSYMBOL_OP_INT_SLESS = 19,              /* OP_INT_SLESS  */
  YYSYMBOL_OP_INT_SLESSEQUAL = 20,         /* OP_INT_SLESSEQUAL  */
  YYSYMBOL_OP_FLOAT_LESS = 21,             /* OP_FLOAT_LESS  */
  YYSYMBOL_OP_FLOAT_LESSEQUAL = 22,        /* OP_FLOAT_LESSEQUAL  */
  YYSYMBOL_OP_INT_LEFT = 23,               /* OP_INT_LEFT  */
  YYSYMBOL_OP_INT_RIGHT = 24,              /* OP_INT_RIGHT  */
  YYSYMBOL_OP_INT_SRIGHT = 25,             /* OP_INT_SRIGHT  */
  YYSYMBOL_OP_INT_ADD = 26,                /* OP_INT_ADD  */
  YYSYMBOL_OP_INT_SUB = 27,                /* OP_INT_SUB  */
  YYSYMBOL_OP_FLOAT_ADD = 28,              /* OP_FLOAT_ADD  */
  YYSYMBOL_OP_FLOAT_SUB = 29,              /* OP_FLOAT_SUB  */
  YYSYMBOL_OP_INT_SDIV = 30,               /* OP_INT_SDIV  */
  YYSYMBOL_OP_INT_SREM = 31,               /* OP_INT_SREM  */
  YYSYMBOL_OP_FLOAT_MULT = 32,             /* OP_FLOAT_MULT  */
  YYSYMBOL_OP_FLOAT_DIV = 33,              /* OP_FLOAT_DIV  */
  YYSYMBOL_OP_INT_MULT = 34,               /* OP_INT_MULT  */
  YYSYMBOL_OP_INT_DIV = 35,                /* OP_INT_DIV  */
  YYSYMBOL_OP_INT_REM = 36,                /* OP_INT_REM  */
  YYSYMBOL_OP_BOOL_NEGATE = 37,            /* OP_BOOL_NEGATE  */
  YYSYMBOL_OP_INT_NEGATE = 38,             /* OP_INT_NEGATE  */
  YYSYMBOL_OP_INT_ZEXT = 39,               /* OP_INT_ZEXT  */
  YYSYMBOL_OP_INT_CARRY = 40,              /* OP_INT_CARRY  */
  YYSYMBOL_OP_INT_BORROW = 41,             /* OP_INT_BORROW  */
  YYSYMBOL_OP_INT_SEXT = 42,               /* OP_INT_SEXT  */
  YYSYMBOL_OP_INT_SCARRY = 43,             /* OP_INT_SCARRY  */
  YYSYMBOL_OP_INT_SBORROW = 44,            /* OP_INT_SBORROW  */
  YYSYMBOL_OP_FLOAT_NAN = 45,              /* OP_FLOAT_NAN  */
  YYSYMBOL_OP_FLOAT_ABS = 46,              /* OP_FLOAT_ABS  */
  YYSYMBOL_OP_FLOAT_SQRT = 47,             /* OP_FLOAT_SQRT  */
  YYSYMBOL_OP_FLOAT_CEIL = 48,             /* OP_FLOAT_CEIL  */
  YYSYMBOL_OP_FLOAT_FLOOR = 49,            /* OP_FLOAT_FLOOR  */
  YYSYMBOL_OP_FLOAT_ROUND = 50,            /* OP_FLOAT_ROUND  */
  YYSYMBOL_OP_FLOAT_INT2FLOAT = 51,        /* OP_FLOAT_INT2FLOAT  */
  YYSYMBOL_OP_FLOAT_FLOAT2FLOAT = 52,      /* OP_FLOAT_FLOAT2FLOAT  */
  YYSYMBOL_OP_FLOAT_TRUNC = 53,            /* OP_FLOAT_TRUNC  */
  YYSYMBOL_OP_BRANCH = 54,                 /* OP_BRANCH  */
  YYSYMBOL_OP_BRANCHIND = 55,              /* OP_BRANCHIND  */
  YYSYMBOL_OP_CALL = 56,                   /* OP_CALL  */
  YYSYMBOL_OP_CALLIND = 57,                /* OP_CALLIND  */
  YYSYMBOL_OP_RETURN = 58,                 /* OP_RETURN  */
  YYSYMBOL_OP_CBRANCH = 59,                /* OP_CBRANCH  */
  YYSYMBOL_OP_CALLOTHER = 60,              /* OP_CALLOTHER  */
  YYSYMBOL_OP_LOAD = 61,                   /* OP_LOAD  */
  YYSYMBOL_OP_STORE = 62,                  /* OP_STORE  */
  YYSYMBOL_OP_PIECE = 63,                  /* OP_PIECE  */
  YYSYMBOL_OP_SUBPIECE = 64,               /* OP_SUBPIECE  */
  YYSYMBOL_OP_COPY = 65,                   /* OP_COPY  */
  YYSYMBOL_BADINTEGER = 66,                /* BADINTEGER  */
  YYSYMBOL_BEFORE_KEYWORD = 67,            /* BEFORE_KEYWORD  */
  YYSYMBOL_AFTER_KEYWORD = 68,             /* AFTER_KEYWORD  */
  YYSYMBOL_REMOVE_KEYWORD = 69,            /* REMOVE_KEYWORD  */
  YYSYMBOL_SET_KEYWORD = 70,               /* SET_KEYWORD  */
  YYSYMBOL_ACTION_TICK = 71,               /* ACTION_TICK  */
  YYSYMBOL_ISTRUE_KEYWORD = 72,            /* ISTRUE_KEYWORD  */
  YYSYMBOL_ISFALSE_KEYWORD = 73,           /* ISFALSE_KEYWORD  */
  YYSYMBOL_CHAR = 74,                      /* CHAR  */
  YYSYMBOL_INTB = 75,                      /* INTB  */
  YYSYMBOL_OP_IDENTIFIER = 76,             /* OP_IDENTIFIER  */
  YYSYMBOL_VAR_IDENTIFIER = 77,            /* VAR_IDENTIFIER  */
  YYSYMBOL_CONST_IDENTIFIER = 78,          /* CONST_IDENTIFIER  */
  YYSYMBOL_OP_NEW_IDENTIFIER = 79,         /* OP_NEW_IDENTIFIER  */
  YYSYMBOL_VAR_NEW_IDENTIFIER = 80,        /* VAR_NEW_IDENTIFIER  */
  YYSYMBOL_DOT_IDENTIFIER = 81,            /* DOT_IDENTIFIER  */
  YYSYMBOL_82_ = 82,                       /* '{'  */
  YYSYMBOL_83_ = 83,                       /* '}'  */
  YYSYMBOL_84_ = 84,                       /* '['  */
  YYSYMBOL_85_ = 85,                       /* ']'  */
  YYSYMBOL_86_ = 86,                       /* ';'  */
  YYSYMBOL_87_ = 87,                       /* '('  */
  YYSYMBOL_88_ = 88,                       /* ')'  */
  YYSYMBOL_89_ = 89,                       /* '='  */
  YYSYMBOL_90_ = 90,                       /* ':'  */
  YYSYMBOL_YYACCEPT = 91,                  /* $accept  */
  YYSYMBOL_fullrule = 92,                  /* fullrule  */
  YYSYMBOL_megaormid = 93,                 /* megaormid  */
  YYSYMBOL_actionlist = 94,                /* actionlist  */
  YYSYMBOL_statementlist = 95,             /* statementlist  */
  YYSYMBOL_action = 96,                    /* action  */
  YYSYMBOL_orgroupmid = 97,                /* orgroupmid  */
  YYSYMBOL_statement = 98,                 /* statement  */
  YYSYMBOL_opnode = 99,                    /* opnode  */
  YYSYMBOL_varnode = 100,                  /* varnode  */
  YYSYMBOL_deadnode = 101,                 /* deadnode  */
  YYSYMBOL_opnewnode = 102,                /* opnewnode  */
  YYSYMBOL_varnewnode = 103,               /* varnewnode  */
  YYSYMBOL_deadnewnode = 104,              /* deadnewnode  */
  YYSYMBOL_rhs_const = 105,                /* rhs_const  */
  YYSYMBOL_var_size = 106,                 /* var_size  */
  YYSYMBOL_number = 107,                   /* number  */
  YYSYMBOL_op_any = 108,                   /* op_any  */
  YYSYMBOL_op_list = 109,                  /* op_list  */
  YYSYMBOL_op_ident = 110,                 /* op_ident  */
  YYSYMBOL_var_ident = 111,                /* var_ident  */
  YYSYMBOL_const_ident = 112,              /* const_ident  */
  YYSYMBOL_op_new_ident = 113,             /* op_new_ident  */
  YYSYMBOL_var_new_ident = 114             /* var_new_ident  */
};
typedef enum yysymbol_kind_t yysymbol_kind_t;




#ifdef short
# undef short
#endif

/* On compilers that do not define __PTRDIFF_MAX__ etc., make sure
   <limits.h> and (if available) <stdint.h> are included
   so that the code can choose integer types of a good width.  */

#ifndef __PTRDIFF_MAX__
# include <limits.h> /* INFRINGES ON USER NAME SPACE */
# if defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stdint.h> /* INFRINGES ON USER NAME SPACE */
#  define YY_STDINT_H
# endif
#endif

/* Narrow types that promote to a signed type and that can represent a
   signed or unsigned integer of at least N bits.  In tables they can
   save space and decrease cache pressure.  Promoting to a signed type
   helps avoid bugs in integer arithmetic.  */

#ifdef __INT_LEAST8_MAX__
typedef __INT_LEAST8_TYPE__ yytype_int8;
#elif defined YY_STDINT_H
typedef int_least8_t yytype_int8;
#else
typedef signed char yytype_int8;
#endif

#ifdef __INT_LEAST16_MAX__
typedef __INT_LEAST16_TYPE__ yytype_int16;
#elif defined YY_STDINT_H
typedef int_least16_t yytype_int16;
#else
typedef short yytype_int16;
#endif

/* Work around bug in HP-UX 11.23, which defines these macros
   incorrectly for preprocessor constants.  This workaround can likely
   be removed in 2023, as HPE has promised support for HP-UX 11.23
   (aka HP-UX 11i v2) only through the end of 2022; see Table 2 of
   <https://h20195.www2.hpe.com/V2/getpdf.aspx/4AA4-7673ENW.pdf>.  */
#ifdef __hpux
# undef UINT_LEAST8_MAX
# undef UINT_LEAST16_MAX
# define UINT_LEAST8_MAX 255
# define UINT_LEAST16_MAX 65535
#endif

#if defined __UINT_LEAST8_MAX__ && __UINT_LEAST8_MAX__ <= __INT_MAX__
typedef __UINT_LEAST8_TYPE__ yytype_uint8;
#elif (!defined __UINT_LEAST8_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST8_MAX <= INT_MAX)
typedef uint_least8_t yytype_uint8;
#elif !defined __UINT_LEAST8_MAX__ && UCHAR_MAX <= INT_MAX
typedef unsigned char yytype_uint8;
#else
typedef short yytype_uint8;
#endif

#if defined __UINT_LEAST16_MAX__ && __UINT_LEAST16_MAX__ <= __INT_MAX__
typedef __UINT_LEAST16_TYPE__ yytype_uint16;
#elif (!defined __UINT_LEAST16_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST16_MAX <= INT_MAX)
typedef uint_least16_t yytype_uint16;
#elif !defined __UINT_LEAST16_MAX__ && USHRT_MAX <= INT_MAX
typedef unsigned short yytype_uint16;
#else
typedef int yytype_uint16;
#endif

#ifndef YYPTRDIFF_T
# if defined __PTRDIFF_TYPE__ && defined __PTRDIFF_MAX__
#  define YYPTRDIFF_T __PTRDIFF_TYPE__
#  define YYPTRDIFF_MAXIMUM __PTRDIFF_MAX__
# elif defined PTRDIFF_MAX
#  ifndef ptrdiff_t
#   include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  endif
#  define YYPTRDIFF_T ptrdiff_t
#  define YYPTRDIFF_MAXIMUM PTRDIFF_MAX
# else
#  define YYPTRDIFF_T long
#  define YYPTRDIFF_MAXIMUM LONG_MAX
# endif
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned
# endif
#endif

#define YYSIZE_MAXIMUM                                  \
  YY_CAST (YYPTRDIFF_T,                                 \
           (YYPTRDIFF_MAXIMUM < YY_CAST (YYSIZE_T, -1)  \
            ? YYPTRDIFF_MAXIMUM                         \
            : YY_CAST (YYSIZE_T, -1)))

#define YYSIZEOF(X) YY_CAST (YYPTRDIFF_T, sizeof (X))


/* Stored state numbers (used for stacks). */
typedef yytype_uint8 yy_state_t;

/* State numbers in computations.  */
typedef int yy_state_fast_t;

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif


#ifndef YY_ATTRIBUTE_PURE
# if defined __GNUC__ && 2 < __GNUC__ + (96 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_PURE __attribute__ ((__pure__))
# else
#  define YY_ATTRIBUTE_PURE
# endif
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# if defined __GNUC__ && 2 < __GNUC__ + (7 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_UNUSED __attribute__ ((__unused__))
# else
#  define YY_ATTRIBUTE_UNUSED
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YY_USE(E) ((void) (E))
#else
# define YY_USE(E) /* empty */
#endif

/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
#if defined __GNUC__ && ! defined __ICC && 406 <= __GNUC__ * 100 + __GNUC_MINOR__
# if __GNUC__ * 100 + __GNUC_MINOR__ < 407
#  define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                           \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")
# else
#  define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                           \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")              \
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# endif
# define YY_IGNORE_MAYBE_UNINITIALIZED_END      \
    _Pragma ("GCC diagnostic pop")
#else
# define YY_INITIAL_VALUE(Value) Value
#endif
#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) /* Nothing. */
#endif

#if defined __cplusplus && defined __GNUC__ && ! defined __ICC && 6 <= __GNUC__
# define YY_IGNORE_USELESS_CAST_BEGIN                          \
    _Pragma ("GCC diagnostic push")                            \
    _Pragma ("GCC diagnostic ignored \"-Wuseless-cast\"")
# define YY_IGNORE_USELESS_CAST_END            \
    _Pragma ("GCC diagnostic pop")
#endif
#ifndef YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_END
#endif


#define YY_ASSERT(E) ((void) (0 && (E)))

#if !defined yyoverflow

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
      /* Use EXIT_SUCCESS as a witness for stdlib.h.  */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's 'empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
             && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* !defined yyoverflow */

#if (! defined yyoverflow \
     && (! defined __cplusplus \
         || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yy_state_t yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (YYSIZEOF (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (YYSIZEOF (yy_state_t) + YYSIZEOF (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)                           \
    do                                                                  \
      {                                                                 \
        YYPTRDIFF_T yynewbytes;                                         \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * YYSIZEOF (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / YYSIZEOF (*yyptr);                        \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, YY_CAST (YYSIZE_T, (Count)) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYPTRDIFF_T yyi;                      \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (0)
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  4
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   626

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  91
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  24
/* YYNRULES -- Number of rules.  */
#define YYNRULES  140
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  233

/* YYMAXUTOK -- Last valid token kind.  */
#define YYMAXUTOK   336


/* YYTRANSLATE(TOKEN-NUM) -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, with out-of-bounds checking.  */
#define YYTRANSLATE(YYX)                                \
  (0 <= (YYX) && (YYX) <= YYMAXUTOK                     \
   ? YY_CAST (yysymbol_kind_t, yytranslate[YYX])        \
   : YYSYMBOL_YYUNDEF)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex.  */
static const yytype_int8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
      87,    88,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,    90,    86,
       2,    89,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,    84,     2,    85,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    82,     2,    83,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    56,    57,    58,    59,    60,    61,    62,    63,    64,
      65,    66,    67,    68,    69,    70,    71,    72,    73,    74,
      75,    76,    77,    78,    79,    80,    81
};

#if YYDEBUG
/* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_int16 yyrline[] =
{
       0,    77,    77,    78,    81,    82,    85,    86,    89,    90,
      93,    94,    95,    98,    99,   102,   103,   104,   105,   106,
     109,   110,   111,   112,   113,   114,   115,   118,   119,   120,
     121,   122,   123,   126,   127,   128,   129,   130,   131,   132,
     135,   136,   137,   138,   139,   140,   143,   144,   145,   146,
     149,   150,   153,   154,   155,   156,   157,   158,   159,   160,
     161,   162,   163,   164,   165,   166,   167,   168,   169,   170,
     171,   172,   175,   176,   179,   180,   183,   184,   185,   186,
     187,   188,   189,   190,   191,   192,   193,   194,   195,   196,
     197,   198,   199,   200,   201,   202,   203,   204,   205,   206,
     207,   208,   209,   210,   211,   212,   213,   214,   215,   216,
     217,   218,   219,   220,   221,   222,   223,   224,   225,   226,
     227,   228,   229,   230,   231,   232,   233,   234,   235,   236,
     237,   238,   239,   240,   243,   244,   247,   250,   253,   256,
     259
};
#endif

/** Accessing symbol of state STATE.  */
#define YY_ACCESSING_SYMBOL(State) YY_CAST (yysymbol_kind_t, yystos[State])

#if YYDEBUG || 0
/* The user-facing name of the symbol whose (internal) number is
   YYSYMBOL.  No bounds checking.  */
static const char *yysymbol_name (yysymbol_kind_t yysymbol) YY_ATTRIBUTE_UNUSED;

/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "\"end of file\"", "error", "\"invalid token\"", "RIGHT_ARROW",
  "LEFT_ARROW", "DOUBLE_RIGHT_ARROW", "DOUBLE_LEFT_ARROW", "OP_BOOL_OR",
  "OP_BOOL_AND", "OP_BOOL_XOR", "OP_INT_OR", "OP_INT_XOR", "OP_INT_AND",
  "OP_INT_EQUAL", "OP_INT_NOTEQUAL", "OP_FLOAT_EQUAL", "OP_FLOAT_NOTEQUAL",
  "OP_INT_LESS", "OP_INT_LESSEQUAL", "OP_INT_SLESS", "OP_INT_SLESSEQUAL",
  "OP_FLOAT_LESS", "OP_FLOAT_LESSEQUAL", "OP_INT_LEFT", "OP_INT_RIGHT",
  "OP_INT_SRIGHT", "OP_INT_ADD", "OP_INT_SUB", "OP_FLOAT_ADD",
  "OP_FLOAT_SUB", "OP_INT_SDIV", "OP_INT_SREM", "OP_FLOAT_MULT",
  "OP_FLOAT_DIV", "OP_INT_MULT", "OP_INT_DIV", "OP_INT_REM",
  "OP_BOOL_NEGATE", "OP_INT_NEGATE", "OP_INT_ZEXT", "OP_INT_CARRY",
  "OP_INT_BORROW", "OP_INT_SEXT", "OP_INT_SCARRY", "OP_INT_SBORROW",
  "OP_FLOAT_NAN", "OP_FLOAT_ABS", "OP_FLOAT_SQRT", "OP_FLOAT_CEIL",
  "OP_FLOAT_FLOOR", "OP_FLOAT_ROUND", "OP_FLOAT_INT2FLOAT",
  "OP_FLOAT_FLOAT2FLOAT", "OP_FLOAT_TRUNC", "OP_BRANCH", "OP_BRANCHIND",
  "OP_CALL", "OP_CALLIND", "OP_RETURN", "OP_CBRANCH", "OP_CALLOTHER",
  "OP_LOAD", "OP_STORE", "OP_PIECE", "OP_SUBPIECE", "OP_COPY",
  "BADINTEGER", "BEFORE_KEYWORD", "AFTER_KEYWORD", "REMOVE_KEYWORD",
  "SET_KEYWORD", "ACTION_TICK", "ISTRUE_KEYWORD", "ISFALSE_KEYWORD",
  "CHAR", "INTB", "OP_IDENTIFIER", "VAR_IDENTIFIER", "CONST_IDENTIFIER",
  "OP_NEW_IDENTIFIER", "VAR_NEW_IDENTIFIER", "DOT_IDENTIFIER", "'{'",
  "'}'", "'['", "']'", "';'", "'('", "')'", "'='", "':'", "$accept",
  "fullrule", "megaormid", "actionlist", "statementlist", "action",
  "orgroupmid", "statement", "opnode", "varnode", "deadnode", "opnewnode",
  "varnewnode", "deadnewnode", "rhs_const", "var_size", "number", "op_any",
  "op_list", "op_ident", "var_ident", "const_ident", "op_new_ident",
  "var_new_ident", YY_NULLPTR
};

static const char *
yysymbol_name (yysymbol_kind_t yysymbol)
{
  return yytname[yysymbol];
}
#endif

#define YYPACT_NINF (-137)

#define yypact_value_is_default(Yyn) \
  ((Yyn) == YYPACT_NINF)

#define YYTABLE_NINF (-1)

#define yytable_value_is_error(Yyn) \
  ((Yyn) == YYTABLE_NINF)

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
static const yytype_int16 yypact[] =
{
     -62,  -137,    11,   113,  -137,  -137,   -63,   -61,  -137,  -137,
    -137,  -137,  -137,    84,  -137,     0,     4,   -64,  -137,  -137,
     -52,    -2,    -2,    -5,   513,    -1,   526,  -137,  -137,  -137,
       9,   -47,   -27,  -137,   -17,     2,   -71,  -137,   388,     1,
     -18,     1,  -137,    17,    -2,  -137,    -2,     6,  -137,    -2,
      88,  -137,     7,  -137,   261,  -137,    -9,  -137,   -41,  -137,
    -137,  -137,     3,     5,  -137,    12,  -137,  -137,   447,  -137,
      19,  -137,  -137,  -137,  -137,  -137,  -137,  -137,     1,     1,
    -137,  -137,  -137,  -137,  -137,  -137,  -137,  -137,  -137,  -137,
    -137,  -137,  -137,  -137,  -137,  -137,  -137,  -137,  -137,  -137,
    -137,  -137,  -137,  -137,  -137,  -137,  -137,  -137,  -137,  -137,
    -137,  -137,  -137,  -137,  -137,  -137,  -137,  -137,  -137,  -137,
    -137,  -137,  -137,  -137,  -137,  -137,  -137,  -137,  -137,  -137,
    -137,   205,  -137,     1,  -137,  -137,     2,     2,    37,     7,
     333,  -137,   287,    -2,    -2,    -2,    -2,    -2,    -2,    -2,
      -2,    -2,    -2,    -2,    -2,    -2,    -2,    -2,    -2,  -137,
    -137,  -137,   513,  -137,   539,   539,  -137,    29,    -2,   447,
    -137,  -137,   -24,    16,    31,    36,  -137,  -137,  -137,    42,
      44,    -2,  -137,  -137,   502,   521,   540,   346,   346,   553,
     553,   553,   553,    83,    83,    83,    18,    18,  -137,  -137,
     -41,   -65,   306,    49,   -41,   -41,    -2,  -137,  -137,  -137,
    -137,   333,    68,    69,    51,  -137,    70,    77,    78,    80,
     333,     7,  -137,  -137,  -137,    37,     7,  -137,  -137,  -137,
    -137,  -137,  -137
};

/* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
   Performed when YYTABLE does not specify something else to do.  Zero
   means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
       0,     8,     0,     0,     1,     6,     0,     0,   136,   137,
     138,     8,     8,     0,     9,     0,     0,     0,    20,    27,
       0,     0,     0,     0,    13,     0,     0,   139,     2,     7,
       0,     0,     0,    44,     0,     0,     0,    15,     0,     0,
       0,     0,    16,     0,     0,    17,     0,     0,    74,     0,
       0,    52,     0,    54,     0,     8,     0,     8,     4,     8,
      18,    19,     0,     0,    10,     0,    11,    12,     0,    30,
       0,    29,    76,    77,    78,    84,    85,    83,    91,    92,
     109,   110,    93,    94,    98,    99,   111,   112,    90,    89,
      97,    81,    82,   105,   106,    95,    96,   107,   108,    86,
      87,    88,    79,    80,   100,   101,   102,   103,   104,   113,
     114,   115,   116,   117,   118,   119,   120,   121,   122,   123,
     124,   125,   126,   127,   128,   129,   130,   131,   132,   133,
     134,     0,    34,     0,    23,    22,     0,     0,    72,    35,
      37,    75,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,    38,
      55,    39,     0,     3,    13,    14,   140,     0,     0,     0,
      91,    92,     0,     0,     0,     0,    21,   135,    24,     0,
       0,     0,    36,    53,    59,    60,    58,    63,    64,    65,
      66,    67,    68,    69,    70,    71,    56,    57,    61,    62,
       5,     0,     0,     0,     0,     0,     0,    25,    26,    31,
      32,    73,     0,     0,     0,    45,     0,     0,     0,     0,
      33,    28,    46,    47,    51,    72,    48,    49,    40,    42,
      41,    43,    50
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
    -137,  -137,  -137,    -7,   124,  -137,  -137,  -137,  -137,  -137,
    -137,  -137,  -137,  -137,    -4,  -128,  -137,   -66,  -137,   -12,
      -3,    10,  -136,   -89
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_uint8 yydefgoto[] =
{
       0,     2,    23,    13,     3,    29,    25,    14,    15,    16,
      17,    30,    31,    32,    50,   182,    51,   130,   131,    18,
      52,    53,    34,   167
};

/* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule whose
   number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int16 yytable[] =
{
      19,    33,   172,    35,    36,    55,     9,    40,    41,    59,
     212,     4,     9,    20,    62,    63,    70,    58,    54,   133,
       1,    19,    45,    19,    21,    47,    22,   132,   134,   135,
     136,   137,    69,    71,    20,     8,    20,    46,    27,    66,
     138,   139,   140,   204,   205,   142,    33,   143,   144,   145,
     146,   147,   157,   158,   148,   149,   150,   151,     8,    67,
     152,   153,   154,   155,   156,   177,   174,   175,   217,   219,
      68,   157,   158,    48,   163,     9,    10,     8,    47,     9,
      56,   141,   169,   166,    60,    49,    37,    38,   160,    39,
      42,    43,   168,    44,   173,    64,    65,   232,   143,   144,
     145,   146,   147,   203,   206,   148,   149,   150,   151,   155,
     156,   152,   153,   154,   155,   156,   201,   157,   158,   207,
     224,   178,   157,   158,   208,   227,    48,   181,     9,    10,
     209,   166,   210,   179,   180,    24,    26,   215,    49,   184,
     185,   186,   187,   188,   189,   190,   191,   192,   193,   194,
     195,   196,   197,   198,   199,   200,   222,   223,   228,    19,
       8,    19,    19,    27,   202,   229,   230,    28,   231,     0,
       0,     0,    20,     0,    20,    20,   159,   211,     0,   162,
       0,   164,     0,   165,     5,     6,     7,     0,    33,     8,
       9,    10,   216,   218,     0,     0,     0,    11,   213,     0,
      12,     0,   220,   221,     0,     0,     0,     0,     0,     0,
     225,   226,    72,    73,    74,    75,    76,    77,   170,   171,
      80,    81,    82,    83,    84,    85,    86,    87,    88,    89,
      90,    91,    92,    93,    94,    95,    96,    97,    98,    99,
     100,   101,   102,   103,   104,   105,     0,   106,   107,   108,
     109,   110,   111,   112,   113,   114,   115,   116,   117,   118,
     119,   120,   121,   122,   123,   124,   125,   126,   127,   128,
     129,   143,   144,   145,   146,   147,     0,     0,   148,   149,
     150,   151,     0,     0,   152,   153,   154,   155,   156,     0,
       0,     0,     0,   176,     0,   157,   158,   143,   144,   145,
     146,   147,     0,     0,   148,   149,   150,   151,     0,     0,
     152,   153,   154,   155,   156,     0,   143,   144,   145,   146,
     147,   157,   158,   148,   149,   150,   151,     0,     0,   152,
     153,   154,   155,   156,     0,     0,     0,     0,     0,     0,
     157,   158,     0,   143,   144,   145,   146,   147,     0,   161,
     148,   149,   150,   151,     0,     0,   152,   153,   154,   155,
     156,     0,     0,   148,   149,   150,   151,   157,   158,   152,
     153,   154,   155,   156,     0,   183,     0,     0,     0,     0,
     157,   158,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   214,    72,    73,    74,    75,    76,
      77,    78,    79,    80,    81,    82,    83,    84,    85,    86,
      87,    88,    89,    90,    91,    92,    93,    94,    95,    96,
      97,    98,    99,   100,   101,   102,   103,   104,   105,     0,
     106,   107,   108,   109,   110,   111,   112,   113,   114,   115,
     116,   117,   118,   119,   120,   121,   122,   123,   124,   125,
     126,   127,   128,   129,    72,    73,    74,    75,    76,    77,
     170,   171,    80,    81,    82,    83,    84,    85,    86,    87,
      88,    89,    90,    91,    92,    93,    94,    95,    96,    97,
      98,    99,   100,   101,   102,   103,   104,   105,     0,   106,
     107,   108,   109,   110,   111,   112,   113,   114,   115,   116,
     117,   118,   119,   120,   121,   122,   123,   124,   125,   126,
     127,   128,   129,   144,   145,   146,   147,     0,     0,   148,
     149,   150,   151,     0,     0,   152,   153,   154,   155,   156,
       0,     0,     0,   145,   146,   147,   157,   158,   148,   149,
     150,   151,     0,     0,   152,   153,   154,   155,   156,     0,
       0,     0,     0,   146,   147,   157,   158,   148,   149,   150,
     151,     0,     0,   152,   153,   154,   155,   156,     0,     0,
      -1,    -1,    -1,    -1,   157,   158,   152,   153,   154,   155,
     156,     0,     0,     0,     5,     6,     7,   157,   158,     8,
       9,    10,     0,     0,     0,     0,     0,    57,     6,     7,
      12,     0,     8,     9,    10,     0,     0,     0,     0,     0,
      57,     6,     7,    12,    61,     8,     9,    10,     0,     0,
       0,     0,     0,    57,     0,     0,    12
};

static const yytype_int16 yycheck[] =
{
       3,    13,    68,     3,     4,    10,    77,     3,     4,    10,
      75,     0,    77,     3,     5,     6,    87,    24,    22,    37,
      82,    24,    86,    26,    87,    27,    87,    39,    40,    41,
      13,    14,    35,    36,    24,    76,    26,    89,    79,    86,
      44,    44,    46,    67,    68,    49,    58,    10,    11,    12,
      13,    14,    34,    35,    17,    18,    19,    20,    76,    86,
      23,    24,    25,    26,    27,   131,    78,    79,   204,   205,
      87,    34,    35,    75,    83,    77,    78,    76,    27,    77,
      85,    75,    70,    80,    85,    87,    86,    87,    81,    89,
      86,    87,    87,    89,    75,    86,    87,   225,    10,    11,
      12,    13,    14,   169,    88,    17,    18,    19,    20,    26,
      27,    23,    24,    25,    26,    27,    87,    34,    35,    88,
      69,   133,    34,    35,    88,   214,    75,    90,    77,    78,
      88,    80,    88,   136,   137,    11,    12,    88,    87,   143,
     144,   145,   146,   147,   148,   149,   150,   151,   152,   153,
     154,   155,   156,   157,   158,   162,    88,    88,    88,   162,
      76,   164,   165,    79,   168,    88,    88,    83,    88,    -1,
      -1,    -1,   162,    -1,   164,   165,    88,   181,    -1,    55,
      -1,    57,    -1,    59,    71,    72,    73,    -1,   200,    76,
      77,    78,   204,   205,    -1,    -1,    -1,    84,   201,    -1,
      87,    -1,   206,   206,    -1,    -1,    -1,    -1,    -1,    -1,
     214,   214,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    -1,    42,    43,    44,
      45,    46,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    56,    57,    58,    59,    60,    61,    62,    63,    64,
      65,    10,    11,    12,    13,    14,    -1,    -1,    17,    18,
      19,    20,    -1,    -1,    23,    24,    25,    26,    27,    -1,
      -1,    -1,    -1,    88,    -1,    34,    35,    10,    11,    12,
      13,    14,    -1,    -1,    17,    18,    19,    20,    -1,    -1,
      23,    24,    25,    26,    27,    -1,    10,    11,    12,    13,
      14,    34,    35,    17,    18,    19,    20,    -1,    -1,    23,
      24,    25,    26,    27,    -1,    -1,    -1,    -1,    -1,    -1,
      34,    35,    -1,    10,    11,    12,    13,    14,    -1,    88,
      17,    18,    19,    20,    -1,    -1,    23,    24,    25,    26,
      27,    -1,    -1,    17,    18,    19,    20,    34,    35,    23,
      24,    25,    26,    27,    -1,    88,    -1,    -1,    -1,    -1,
      34,    35,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    88,     7,     8,     9,    10,    11,
      12,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,    -1,
      42,    43,    44,    45,    46,    47,    48,    49,    50,    51,
      52,    53,    54,    55,    56,    57,    58,    59,    60,    61,
      62,    63,    64,    65,     7,     8,     9,    10,    11,    12,
      13,    14,    15,    16,    17,    18,    19,    20,    21,    22,
      23,    24,    25,    26,    27,    28,    29,    30,    31,    32,
      33,    34,    35,    36,    37,    38,    39,    40,    -1,    42,
      43,    44,    45,    46,    47,    48,    49,    50,    51,    52,
      53,    54,    55,    56,    57,    58,    59,    60,    61,    62,
      63,    64,    65,    11,    12,    13,    14,    -1,    -1,    17,
      18,    19,    20,    -1,    -1,    23,    24,    25,    26,    27,
      -1,    -1,    -1,    12,    13,    14,    34,    35,    17,    18,
      19,    20,    -1,    -1,    23,    24,    25,    26,    27,    -1,
      -1,    -1,    -1,    13,    14,    34,    35,    17,    18,    19,
      20,    -1,    -1,    23,    24,    25,    26,    27,    -1,    -1,
      17,    18,    19,    20,    34,    35,    23,    24,    25,    26,
      27,    -1,    -1,    -1,    71,    72,    73,    34,    35,    76,
      77,    78,    -1,    -1,    -1,    -1,    -1,    84,    72,    73,
      87,    -1,    76,    77,    78,    -1,    -1,    -1,    -1,    -1,
      84,    72,    73,    87,    88,    76,    77,    78,    -1,    -1,
      -1,    -1,    -1,    84,    -1,    -1,    87
};

/* YYSTOS[STATE-NUM] -- The symbol kind of the accessing symbol of
   state STATE-NUM.  */
static const yytype_int8 yystos[] =
{
       0,    82,    92,    95,     0,    71,    72,    73,    76,    77,
      78,    84,    87,    94,    98,    99,   100,   101,   110,   111,
     112,    87,    87,    93,    95,    97,    95,    79,    83,    96,
     102,   103,   104,   110,   113,     3,     4,    86,    87,    89,
       3,     4,    86,    87,    89,    86,    89,    27,    75,    87,
     105,   107,   111,   112,   105,    10,    85,    84,    94,    10,
      85,    88,     5,     6,    86,    87,    86,    86,    87,   111,
      87,   111,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    42,    43,    44,    45,
      46,    47,    48,    49,    50,    51,    52,    53,    54,    55,
      56,    57,    58,    59,    60,    61,    62,    63,    64,    65,
     108,   109,   110,    37,   110,   110,    13,    14,   105,   111,
     105,    75,   105,    10,    11,    12,    13,    14,    17,    18,
      19,    20,    23,    24,    25,    26,    27,    34,    35,    88,
      81,    88,    95,    83,    95,    95,    80,   114,    87,    70,
      13,    14,   108,    75,   110,   110,    88,   108,   110,   111,
     111,    90,   106,    88,   105,   105,   105,   105,   105,   105,
     105,   105,   105,   105,   105,   105,   105,   105,   105,   105,
      94,    87,   105,   108,    67,    68,    88,    88,    88,    88,
      88,   105,    75,   111,    88,    88,   110,   113,   110,   113,
     105,   111,    88,    88,    69,   105,   111,   114,    88,    88,
      88,    88,   106
};

/* YYR1[RULE-NUM] -- Symbol kind of the left-hand side of rule RULE-NUM.  */
static const yytype_int8 yyr1[] =
{
       0,    91,    92,    92,    93,    93,    94,    94,    95,    95,
      96,    96,    96,    97,    97,    98,    98,    98,    98,    98,
      99,    99,    99,    99,    99,    99,    99,   100,   100,   100,
     100,   100,   100,   101,   101,   101,   101,   101,   101,   101,
     102,   102,   102,   102,   102,   102,   103,   103,   103,   103,
     104,   104,   105,   105,   105,   105,   105,   105,   105,   105,
     105,   105,   105,   105,   105,   105,   105,   105,   105,   105,
     105,   105,   106,   106,   107,   107,   108,   108,   108,   108,
     108,   108,   108,   108,   108,   108,   108,   108,   108,   108,
     108,   108,   108,   108,   108,   108,   108,   108,   108,   108,
     108,   108,   108,   108,   108,   108,   108,   108,   108,   108,
     108,   108,   108,   108,   108,   108,   108,   108,   108,   108,
     108,   108,   108,   108,   108,   108,   108,   108,   108,   108,
     108,   108,   108,   108,   109,   109,   110,   111,   112,   113,
     114
};

/* YYR2[RULE-NUM] -- Number of symbols on the right-hand side of rule RULE-NUM.  */
static const yytype_int8 yyr2[] =
{
       0,     2,     4,     6,     2,     4,     1,     2,     0,     2,
       2,     2,     2,     1,     3,     2,     2,     2,     3,     3,
       1,     4,     3,     3,     4,     5,     5,     1,     6,     3,
       3,     5,     5,     6,     3,     3,     4,     3,     4,     4,
       6,     6,     6,     6,     1,     5,     6,     6,     6,     6,
       7,     6,     1,     3,     1,     2,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
       3,     3,     0,     2,     1,     2,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     2,     1,     1,     1,     1,
       1
};


enum { YYENOMEM = -2 };

#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab
#define YYNOMEM         goto yyexhaustedlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                    \
  do                                                              \
    if (yychar == YYEMPTY)                                        \
      {                                                           \
        yychar = (Token);                                         \
        yylval = (Value);                                         \
        YYPOPSTACK (yylen);                                       \
        yystate = *yyssp;                                         \
        goto yybackup;                                            \
      }                                                           \
    else                                                          \
      {                                                           \
        yyerror (YY_("syntax error: cannot back up")); \
        YYERROR;                                                  \
      }                                                           \
  while (0)

/* Backward compatibility with an undocumented macro.
   Use YYerror or YYUNDEF. */
#define YYERRCODE YYUNDEF


/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)                        \
do {                                            \
  if (yydebug)                                  \
    YYFPRINTF Args;                             \
} while (0)




# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Kind, Value); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*-----------------------------------.
| Print this symbol's value on YYO.  |
`-----------------------------------*/

static void
yy_symbol_value_print (FILE *yyo,
                       yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep)
{
  FILE *yyoutput = yyo;
  YY_USE (yyoutput);
  if (!yyvaluep)
    return;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YY_USE (yykind);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}


/*---------------------------.
| Print this symbol on YYO.  |
`---------------------------*/

static void
yy_symbol_print (FILE *yyo,
                 yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep)
{
  YYFPRINTF (yyo, "%s %s (",
             yykind < YYNTOKENS ? "token" : "nterm", yysymbol_name (yykind));

  yy_symbol_value_print (yyo, yykind, yyvaluep);
  YYFPRINTF (yyo, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yy_state_t *yybottom, yy_state_t *yytop)
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)                            \
do {                                                            \
  if (yydebug)                                                  \
    yy_stack_print ((Bottom), (Top));                           \
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

static void
yy_reduce_print (yy_state_t *yyssp, YYSTYPE *yyvsp,
                 int yyrule)
{
  int yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %d):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       YY_ACCESSING_SYMBOL (+yyssp[yyi + 1 - yynrhs]),
                       &yyvsp[(yyi + 1) - (yynrhs)]);
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyssp, yyvsp, Rule); \
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args) ((void) 0)
# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif






/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg,
            yysymbol_kind_t yykind, YYSTYPE *yyvaluep)
{
  YY_USE (yyvaluep);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yykind, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YY_USE (yykind);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}


/* Lookahead token kind.  */
int yychar;

/* The semantic value of the lookahead symbol.  */
YYSTYPE yylval;
/* Number of syntax errors so far.  */
int yynerrs;




/*----------.
| yyparse.  |
`----------*/

int
yyparse (void)
{
    yy_state_fast_t yystate = 0;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus = 0;

    /* Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* Their size.  */
    YYPTRDIFF_T yystacksize = YYINITDEPTH;

    /* The state stack: array, bottom, top.  */
    yy_state_t yyssa[YYINITDEPTH];
    yy_state_t *yyss = yyssa;
    yy_state_t *yyssp = yyss;

    /* The semantic value stack: array, bottom, top.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs = yyvsa;
    YYSTYPE *yyvsp = yyvs;

  int yyn;
  /* The return value of yyparse.  */
  int yyresult;
  /* Lookahead symbol kind.  */
  yysymbol_kind_t yytoken = YYSYMBOL_YYEMPTY;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;



#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yychar = YYEMPTY; /* Cause a token to be read.  */

  goto yysetstate;


/*------------------------------------------------------------.
| yynewstate -- push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;


/*--------------------------------------------------------------------.
| yysetstate -- set current state (the top of the stack) to yystate.  |
`--------------------------------------------------------------------*/
yysetstate:
  YYDPRINTF ((stderr, "Entering state %d\n", yystate));
  YY_ASSERT (0 <= yystate && yystate < YYNSTATES);
  YY_IGNORE_USELESS_CAST_BEGIN
  *yyssp = YY_CAST (yy_state_t, yystate);
  YY_IGNORE_USELESS_CAST_END
  YY_STACK_PRINT (yyss, yyssp);

  if (yyss + yystacksize - 1 <= yyssp)
#if !defined yyoverflow && !defined YYSTACK_RELOCATE
    YYNOMEM;
#else
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYPTRDIFF_T yysize = yyssp - yyss + 1;

# if defined yyoverflow
      {
        /* Give user a chance to reallocate the stack.  Use copies of
           these so that the &'s don't force the real ones into
           memory.  */
        yy_state_t *yyss1 = yyss;
        YYSTYPE *yyvs1 = yyvs;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * YYSIZEOF (*yyssp),
                    &yyvs1, yysize * YYSIZEOF (*yyvsp),
                    &yystacksize);
        yyss = yyss1;
        yyvs = yyvs1;
      }
# else /* defined YYSTACK_RELOCATE */
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
        YYNOMEM;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yy_state_t *yyss1 = yyss;
        union yyalloc *yyptr =
          YY_CAST (union yyalloc *,
                   YYSTACK_ALLOC (YY_CAST (YYSIZE_T, YYSTACK_BYTES (yystacksize))));
        if (! yyptr)
          YYNOMEM;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
#  undef YYSTACK_RELOCATE
        if (yyss1 != yyssa)
          YYSTACK_FREE (yyss1);
      }
# endif

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YY_IGNORE_USELESS_CAST_BEGIN
      YYDPRINTF ((stderr, "Stack size increased to %ld\n",
                  YY_CAST (long, yystacksize)));
      YY_IGNORE_USELESS_CAST_END

      if (yyss + yystacksize - 1 <= yyssp)
        YYABORT;
    }
#endif /* !defined yyoverflow && !defined YYSTACK_RELOCATE */


  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;


/*-----------.
| yybackup.  |
`-----------*/
yybackup:
  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either empty, or end-of-input, or a valid lookahead.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token\n"));
      yychar = yylex ();
    }

  if (yychar <= YYEOF)
    {
      yychar = YYEOF;
      yytoken = YYSYMBOL_YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else if (yychar == YYerror)
    {
      /* The scanner already issued an error message, process directly
         to error recovery.  But do not keep the error token as
         lookahead, it is too special and may lead us to an endless
         loop in error recovery. */
      yychar = YYUNDEF;
      yytoken = YYSYMBOL_YYerror;
      goto yyerrlab1;
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);
  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  /* Discard the shifted token.  */
  yychar = YYEMPTY;
  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     '$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
  case 2: /* fullrule: '{' statementlist actionlist '}'  */
#line 77 "src/ruleparse.y"
                                 { rulecompile->setFullRule( rulecompile->mergeGroups((yyvsp[-2].group),(yyvsp[-1].group)) ); }
#line 1448 "src/ruleparse.cc"
    break;

  case 3: /* fullrule: '{' statementlist '[' megaormid ']' '}'  */
#line 78 "src/ruleparse.y"
                                          { (yyvsp[-4].group)->addConstraint( (yyvsp[-2].group) ); rulecompile->setFullRule( (yyvsp[-4].group) ); }
#line 1454 "src/ruleparse.cc"
    break;

  case 4: /* megaormid: statementlist actionlist  */
#line 81 "src/ruleparse.y"
                                    { (yyval.group) = rulecompile->emptyOrGroup(); rulecompile->addOr((yyval.group),rulecompile->mergeGroups((yyvsp[-1].group),(yyvsp[0].group))); }
#line 1460 "src/ruleparse.cc"
    break;

  case 5: /* megaormid: megaormid OP_INT_OR statementlist actionlist  */
#line 82 "src/ruleparse.y"
                                               { (yyval.group) = rulecompile->addOr((yyvsp[-3].group),rulecompile->mergeGroups((yyvsp[-1].group),(yyvsp[0].group))); }
#line 1466 "src/ruleparse.cc"
    break;

  case 6: /* actionlist: ACTION_TICK  */
#line 85 "src/ruleparse.y"
                        { (yyval.group) = rulecompile->emptyGroup(); }
#line 1472 "src/ruleparse.cc"
    break;

  case 7: /* actionlist: actionlist action  */
#line 86 "src/ruleparse.y"
                    { (yyval.group) = rulecompile->mergeGroups((yyvsp[-1].group),(yyvsp[0].group)); }
#line 1478 "src/ruleparse.cc"
    break;

  case 8: /* statementlist: %empty  */
#line 89 "src/ruleparse.y"
               { (yyval.group) = rulecompile->emptyGroup(); }
#line 1484 "src/ruleparse.cc"
    break;

  case 9: /* statementlist: statementlist statement  */
#line 90 "src/ruleparse.y"
                          { (yyval.group) = rulecompile->mergeGroups((yyvsp[-1].group),(yyvsp[0].group)); }
#line 1490 "src/ruleparse.cc"
    break;

  case 10: /* action: opnewnode ';'  */
#line 93 "src/ruleparse.y"
                      { (yyval.group) = (yyvsp[-1].group); }
#line 1496 "src/ruleparse.cc"
    break;

  case 11: /* action: varnewnode ';'  */
#line 94 "src/ruleparse.y"
                 { (yyval.group) = (yyvsp[-1].group); }
#line 1502 "src/ruleparse.cc"
    break;

  case 12: /* action: deadnewnode ';'  */
#line 95 "src/ruleparse.y"
                  { (yyval.group) = (yyvsp[-1].group); }
#line 1508 "src/ruleparse.cc"
    break;

  case 13: /* orgroupmid: statementlist  */
#line 98 "src/ruleparse.y"
                          { ConstraintGroup *newbase = rulecompile->emptyOrGroup(); (yyval.group) = rulecompile->addOr(newbase,(yyvsp[0].group)); }
#line 1514 "src/ruleparse.cc"
    break;

  case 14: /* orgroupmid: orgroupmid OP_INT_OR statementlist  */
#line 99 "src/ruleparse.y"
                                     { (yyval.group) = rulecompile->addOr((yyvsp[-2].group),(yyvsp[0].group)); }
#line 1520 "src/ruleparse.cc"
    break;

  case 15: /* statement: opnode ';'  */
#line 102 "src/ruleparse.y"
                      { (yyval.group) = (yyvsp[-1].group); }
#line 1526 "src/ruleparse.cc"
    break;

  case 16: /* statement: varnode ';'  */
#line 103 "src/ruleparse.y"
              { (yyval.group) = (yyvsp[-1].group); }
#line 1532 "src/ruleparse.cc"
    break;

  case 17: /* statement: deadnode ';'  */
#line 104 "src/ruleparse.y"
               { (yyval.group) = (yyvsp[-1].group); }
#line 1538 "src/ruleparse.cc"
    break;

  case 18: /* statement: '[' orgroupmid ']'  */
#line 105 "src/ruleparse.y"
                     { (yyval.group) = rulecompile->emptyGroup(); (yyval.group)->addConstraint((yyvsp[-1].group)); }
#line 1544 "src/ruleparse.cc"
    break;

  case 19: /* statement: '(' statementlist ')'  */
#line 106 "src/ruleparse.y"
                        { (yyval.group) = (yyvsp[-1].group); }
#line 1550 "src/ruleparse.cc"
    break;

  case 20: /* opnode: op_ident  */
#line 109 "src/ruleparse.y"
                 { (yyval.group) = rulecompile->newOp((yyvsp[0].id)); }
#line 1556 "src/ruleparse.cc"
    break;

  case 21: /* opnode: opnode '(' op_list ')'  */
#line 110 "src/ruleparse.y"
                         { (yyval.group) = rulecompile->opCodeConstraint((yyvsp[-3].group),(yyvsp[-1].opcodelist)); }
#line 1562 "src/ruleparse.cc"
    break;

  case 22: /* opnode: varnode LEFT_ARROW op_ident  */
#line 111 "src/ruleparse.y"
                              { (yyval.group) = rulecompile->varDef((yyvsp[-2].group),(yyvsp[0].id)); }
#line 1568 "src/ruleparse.cc"
    break;

  case 23: /* opnode: varnode RIGHT_ARROW op_ident  */
#line 112 "src/ruleparse.y"
                               { (yyval.group) = rulecompile->varDescend((yyvsp[-2].group),(yyvsp[0].id)); }
#line 1574 "src/ruleparse.cc"
    break;

  case 24: /* opnode: varnode RIGHT_ARROW OP_BOOL_NEGATE op_ident  */
#line 113 "src/ruleparse.y"
                                              { (yyval.group) = rulecompile->varUniqueDescend((yyvsp[-3].group),(yyvsp[0].id)); }
#line 1580 "src/ruleparse.cc"
    break;

  case 25: /* opnode: opnode '(' OP_INT_EQUAL op_ident ')'  */
#line 114 "src/ruleparse.y"
                                       { (yyval.group) = rulecompile->opCompareConstraint((yyvsp[-4].group),(yyvsp[-1].id),CPUI_INT_EQUAL); }
#line 1586 "src/ruleparse.cc"
    break;

  case 26: /* opnode: opnode '(' OP_INT_NOTEQUAL op_ident ')'  */
#line 115 "src/ruleparse.y"
                                          { (yyval.group) = rulecompile->opCompareConstraint((yyvsp[-4].group),(yyvsp[-1].id),CPUI_INT_NOTEQUAL); }
#line 1592 "src/ruleparse.cc"
    break;

  case 27: /* varnode: var_ident  */
#line 118 "src/ruleparse.y"
                   { (yyval.group) = rulecompile->newVarnode((yyvsp[0].id)); }
#line 1598 "src/ruleparse.cc"
    break;

  case 28: /* varnode: opnode LEFT_ARROW '(' INTB ')' var_ident  */
#line 119 "src/ruleparse.y"
                                           { (yyval.group) = rulecompile->opInput((yyvsp[-5].group),(yyvsp[-2].big),(yyvsp[0].id)); }
#line 1604 "src/ruleparse.cc"
    break;

  case 29: /* varnode: opnode LEFT_ARROW var_ident  */
#line 120 "src/ruleparse.y"
                              { (yyval.group) = rulecompile->opInputAny((yyvsp[-2].group),(yyvsp[0].id)); }
#line 1610 "src/ruleparse.cc"
    break;

  case 30: /* varnode: opnode RIGHT_ARROW var_ident  */
#line 121 "src/ruleparse.y"
                               { (yyval.group) = rulecompile->opOutput((yyvsp[-2].group),(yyvsp[0].id)); }
#line 1616 "src/ruleparse.cc"
    break;

  case 31: /* varnode: varnode '(' OP_INT_EQUAL var_ident ')'  */
#line 122 "src/ruleparse.y"
                                         { (yyval.group) = rulecompile->varCompareConstraint((yyvsp[-4].group),(yyvsp[-1].id),CPUI_INT_EQUAL); }
#line 1622 "src/ruleparse.cc"
    break;

  case 32: /* varnode: varnode '(' OP_INT_NOTEQUAL var_ident ')'  */
#line 123 "src/ruleparse.y"
                                            { (yyval.group) = rulecompile->varCompareConstraint((yyvsp[-4].group),(yyvsp[-1].id),CPUI_INT_NOTEQUAL); }
#line 1628 "src/ruleparse.cc"
    break;

  case 33: /* deadnode: opnode LEFT_ARROW '(' INTB ')' rhs_const  */
#line 126 "src/ruleparse.y"
                                                   { (yyval.group) = rulecompile->opInputConstVal((yyvsp[-5].group),(yyvsp[-2].big),(yyvsp[0].rhsconst)); }
#line 1634 "src/ruleparse.cc"
    break;

  case 34: /* deadnode: opnode '=' op_ident  */
#line 127 "src/ruleparse.y"
                        { (yyval.group) = rulecompile->opCopy((yyvsp[-2].group),(yyvsp[0].id)); }
#line 1640 "src/ruleparse.cc"
    break;

  case 35: /* deadnode: varnode '=' var_ident  */
#line 128 "src/ruleparse.y"
                        { (yyval.group) = rulecompile->varCopy((yyvsp[-2].group),(yyvsp[0].id)); }
#line 1646 "src/ruleparse.cc"
    break;

  case 36: /* deadnode: varnode '=' rhs_const var_size  */
#line 129 "src/ruleparse.y"
                                 { (yyval.group) = rulecompile->varConst((yyvsp[-3].group),(yyvsp[-1].rhsconst),(yyvsp[0].rhsconst)); }
#line 1652 "src/ruleparse.cc"
    break;

  case 37: /* deadnode: const_ident '=' rhs_const  */
#line 130 "src/ruleparse.y"
                            { (yyval.group) = rulecompile->constNamedExpression((yyvsp[-2].id),(yyvsp[0].rhsconst)); }
#line 1658 "src/ruleparse.cc"
    break;

  case 38: /* deadnode: ISTRUE_KEYWORD '(' rhs_const ')'  */
#line 131 "src/ruleparse.y"
                                   { (yyval.group) = rulecompile->booleanConstraint(true,(yyvsp[-1].rhsconst)); }
#line 1664 "src/ruleparse.cc"
    break;

  case 39: /* deadnode: ISFALSE_KEYWORD '(' rhs_const ')'  */
#line 132 "src/ruleparse.y"
                                    { (yyval.group) = rulecompile->booleanConstraint(false,(yyvsp[-1].rhsconst)); }
#line 1670 "src/ruleparse.cc"
    break;

  case 40: /* opnewnode: op_new_ident '(' op_any BEFORE_KEYWORD op_ident ')'  */
#line 135 "src/ruleparse.y"
                                                               { (yyval.group) = rulecompile->opCreation((yyvsp[-5].id),(yyvsp[-3].opcode),false,(yyvsp[-1].id)); }
#line 1676 "src/ruleparse.cc"
    break;

  case 41: /* opnewnode: op_new_ident '(' op_any AFTER_KEYWORD op_ident ')'  */
#line 136 "src/ruleparse.y"
                                                     { (yyval.group) = rulecompile->opCreation((yyvsp[-5].id),(yyvsp[-3].opcode),true,(yyvsp[-1].id)); }
#line 1682 "src/ruleparse.cc"
    break;

  case 42: /* opnewnode: op_new_ident '(' op_any BEFORE_KEYWORD op_new_ident ')'  */
#line 137 "src/ruleparse.y"
                                                          { (yyval.group) = rulecompile->opCreation((yyvsp[-5].id),(yyvsp[-3].opcode),false,(yyvsp[-1].id)); }
#line 1688 "src/ruleparse.cc"
    break;

  case 43: /* opnewnode: op_new_ident '(' op_any AFTER_KEYWORD op_new_ident ')'  */
#line 138 "src/ruleparse.y"
                                                         { (yyval.group) = rulecompile->opCreation((yyvsp[-5].id),(yyvsp[-3].opcode),true,(yyvsp[-1].id)); }
#line 1694 "src/ruleparse.cc"
    break;

  case 44: /* opnewnode: op_ident  */
#line 139 "src/ruleparse.y"
           { (yyval.group) = rulecompile->newOp((yyvsp[0].id)); }
#line 1700 "src/ruleparse.cc"
    break;

  case 45: /* opnewnode: opnewnode '(' SET_KEYWORD op_any ')'  */
#line 140 "src/ruleparse.y"
                                       { (yyval.group) = rulecompile->newSetOpcode((yyvsp[-4].group),(yyvsp[-1].opcode)); }
#line 1706 "src/ruleparse.cc"
    break;

  case 46: /* varnewnode: opnewnode DOUBLE_RIGHT_ARROW var_new_ident '(' INTB ')'  */
#line 143 "src/ruleparse.y"
                                                                    { (yyval.group) = rulecompile->newUniqueOut((yyvsp[-5].group),(yyvsp[-3].id),-((int4)*(yyvsp[-1].big))); delete (yyvsp[-1].big); }
#line 1712 "src/ruleparse.cc"
    break;

  case 47: /* varnewnode: opnewnode DOUBLE_RIGHT_ARROW var_new_ident '(' var_ident ')'  */
#line 144 "src/ruleparse.y"
                                                               { (yyval.group) = rulecompile->newUniqueOut((yyvsp[-5].group),(yyvsp[-3].id),(yyvsp[-1].id)); }
#line 1718 "src/ruleparse.cc"
    break;

  case 48: /* varnewnode: opnewnode DOUBLE_LEFT_ARROW '(' rhs_const ')' var_ident  */
#line 145 "src/ruleparse.y"
                                                          { (yyval.group) = rulecompile->newSetInput((yyvsp[-5].group),(yyvsp[-2].rhsconst),(yyvsp[0].id)); }
#line 1724 "src/ruleparse.cc"
    break;

  case 49: /* varnewnode: opnewnode DOUBLE_LEFT_ARROW '(' rhs_const ')' var_new_ident  */
#line 146 "src/ruleparse.y"
                                                              { (yyval.group) = rulecompile->newSetInput((yyvsp[-5].group),(yyvsp[-2].rhsconst),(yyvsp[0].id)); }
#line 1730 "src/ruleparse.cc"
    break;

  case 50: /* deadnewnode: opnewnode DOUBLE_LEFT_ARROW '(' rhs_const ')' rhs_const var_size  */
#line 149 "src/ruleparse.y"
                                                                              { (yyval.group) = rulecompile->newSetInputConstVal((yyvsp[-6].group),(yyvsp[-3].rhsconst),(yyvsp[-1].rhsconst),(yyvsp[0].rhsconst)); }
#line 1736 "src/ruleparse.cc"
    break;

  case 51: /* deadnewnode: opnewnode DOUBLE_LEFT_ARROW '(' rhs_const ')' REMOVE_KEYWORD  */
#line 150 "src/ruleparse.y"
                                                               { (yyval.group) = rulecompile->removeInput((yyval.group),(yyvsp[-2].rhsconst)); }
#line 1742 "src/ruleparse.cc"
    break;

  case 52: /* rhs_const: number  */
#line 153 "src/ruleparse.y"
                  { (yyval.rhsconst) = rulecompile->constAbsolute((yyvsp[0].big)); }
#line 1748 "src/ruleparse.cc"
    break;

  case 53: /* rhs_const: '(' rhs_const ')'  */
#line 154 "src/ruleparse.y"
                    { (yyval.rhsconst) = (yyvsp[-1].rhsconst); }
#line 1754 "src/ruleparse.cc"
    break;

  case 54: /* rhs_const: const_ident  */
#line 155 "src/ruleparse.y"
              { (yyval.rhsconst) = rulecompile->constNamed((yyvsp[0].id)); }
#line 1760 "src/ruleparse.cc"
    break;

  case 55: /* rhs_const: var_ident DOT_IDENTIFIER  */
#line 156 "src/ruleparse.y"
                           { (yyval.rhsconst) = rulecompile->dotIdentifier((yyvsp[-1].id),(yyvsp[0].str)); }
#line 1766 "src/ruleparse.cc"
    break;

  case 56: /* rhs_const: rhs_const OP_INT_ADD rhs_const  */
#line 157 "src/ruleparse.y"
                                 { (yyval.rhsconst) = rulecompile->constBinaryExpression((yyvsp[-2].rhsconst),CPUI_INT_ADD,(yyvsp[0].rhsconst)); }
#line 1772 "src/ruleparse.cc"
    break;

  case 57: /* rhs_const: rhs_const OP_INT_SUB rhs_const  */
#line 158 "src/ruleparse.y"
                                 { (yyval.rhsconst) = rulecompile->constBinaryExpression((yyvsp[-2].rhsconst),CPUI_INT_SUB,(yyvsp[0].rhsconst)); }
#line 1778 "src/ruleparse.cc"
    break;

  case 58: /* rhs_const: rhs_const OP_INT_AND rhs_const  */
#line 159 "src/ruleparse.y"
                                 { (yyval.rhsconst) = rulecompile->constBinaryExpression((yyvsp[-2].rhsconst),CPUI_INT_AND,(yyvsp[0].rhsconst)); }
#line 1784 "src/ruleparse.cc"
    break;

  case 59: /* rhs_const: rhs_const OP_INT_OR rhs_const  */
#line 160 "src/ruleparse.y"
                                { (yyval.rhsconst) = rulecompile->constBinaryExpression((yyvsp[-2].rhsconst),CPUI_INT_OR,(yyvsp[0].rhsconst)); }
#line 1790 "src/ruleparse.cc"
    break;

  case 60: /* rhs_const: rhs_const OP_INT_XOR rhs_const  */
#line 161 "src/ruleparse.y"
                                 { (yyval.rhsconst) = rulecompile->constBinaryExpression((yyvsp[-2].rhsconst),CPUI_INT_XOR,(yyvsp[0].rhsconst)); }
#line 1796 "src/ruleparse.cc"
    break;

  case 61: /* rhs_const: rhs_const OP_INT_MULT rhs_const  */
#line 162 "src/ruleparse.y"
                                  { (yyval.rhsconst) = rulecompile->constBinaryExpression((yyvsp[-2].rhsconst),CPUI_INT_MULT,(yyvsp[0].rhsconst)); }
#line 1802 "src/ruleparse.cc"
    break;

  case 62: /* rhs_const: rhs_const OP_INT_DIV rhs_const  */
#line 163 "src/ruleparse.y"
                                 { (yyval.rhsconst) = rulecompile->constBinaryExpression((yyvsp[-2].rhsconst),CPUI_INT_DIV,(yyvsp[0].rhsconst)); }
#line 1808 "src/ruleparse.cc"
    break;

  case 63: /* rhs_const: rhs_const OP_INT_EQUAL rhs_const  */
#line 164 "src/ruleparse.y"
                                   { (yyval.rhsconst) = rulecompile->constBinaryExpression((yyvsp[-2].rhsconst),CPUI_INT_EQUAL,(yyvsp[0].rhsconst)); }
#line 1814 "src/ruleparse.cc"
    break;

  case 64: /* rhs_const: rhs_const OP_INT_NOTEQUAL rhs_const  */
#line 165 "src/ruleparse.y"
                                      { (yyval.rhsconst) = rulecompile->constBinaryExpression((yyvsp[-2].rhsconst),CPUI_INT_NOTEQUAL,(yyvsp[0].rhsconst)); }
#line 1820 "src/ruleparse.cc"
    break;

  case 65: /* rhs_const: rhs_const OP_INT_LESS rhs_const  */
#line 166 "src/ruleparse.y"
                                  { (yyval.rhsconst) = rulecompile->constBinaryExpression((yyvsp[-2].rhsconst),CPUI_INT_LESS,(yyvsp[0].rhsconst)); }
#line 1826 "src/ruleparse.cc"
    break;

  case 66: /* rhs_const: rhs_const OP_INT_LESSEQUAL rhs_const  */
#line 167 "src/ruleparse.y"
                                       { (yyval.rhsconst) = rulecompile->constBinaryExpression((yyvsp[-2].rhsconst),CPUI_INT_LESSEQUAL,(yyvsp[0].rhsconst)); }
#line 1832 "src/ruleparse.cc"
    break;

  case 67: /* rhs_const: rhs_const OP_INT_SLESS rhs_const  */
#line 168 "src/ruleparse.y"
                                   { (yyval.rhsconst) = rulecompile->constBinaryExpression((yyvsp[-2].rhsconst),CPUI_INT_SLESS,(yyvsp[0].rhsconst)); }
#line 1838 "src/ruleparse.cc"
    break;

  case 68: /* rhs_const: rhs_const OP_INT_SLESSEQUAL rhs_const  */
#line 169 "src/ruleparse.y"
                                        { (yyval.rhsconst) = rulecompile->constBinaryExpression((yyvsp[-2].rhsconst),CPUI_INT_SLESSEQUAL,(yyvsp[0].rhsconst)); }
#line 1844 "src/ruleparse.cc"
    break;

  case 69: /* rhs_const: rhs_const OP_INT_LEFT rhs_const  */
#line 170 "src/ruleparse.y"
                                  { (yyval.rhsconst) = rulecompile->constBinaryExpression((yyvsp[-2].rhsconst),CPUI_INT_LEFT,(yyvsp[0].rhsconst)); }
#line 1850 "src/ruleparse.cc"
    break;

  case 70: /* rhs_const: rhs_const OP_INT_RIGHT rhs_const  */
#line 171 "src/ruleparse.y"
                                  { (yyval.rhsconst) = rulecompile->constBinaryExpression((yyvsp[-2].rhsconst),CPUI_INT_RIGHT,(yyvsp[0].rhsconst)); }
#line 1856 "src/ruleparse.cc"
    break;

  case 71: /* rhs_const: rhs_const OP_INT_SRIGHT rhs_const  */
#line 172 "src/ruleparse.y"
                                   { (yyval.rhsconst) = rulecompile->constBinaryExpression((yyvsp[-2].rhsconst),CPUI_INT_SRIGHT,(yyvsp[0].rhsconst)); }
#line 1862 "src/ruleparse.cc"
    break;

  case 72: /* var_size: %empty  */
#line 175 "src/ruleparse.y"
                      { (yyval.rhsconst) = (RHSConstant *)0; }
#line 1868 "src/ruleparse.cc"
    break;

  case 73: /* var_size: ':' rhs_const  */
#line 176 "src/ruleparse.y"
                { (yyval.rhsconst) = (yyvsp[0].rhsconst); }
#line 1874 "src/ruleparse.cc"
    break;

  case 74: /* number: INTB  */
#line 179 "src/ruleparse.y"
             { (yyval.big) = (yyvsp[0].big); }
#line 1880 "src/ruleparse.cc"
    break;

  case 75: /* number: OP_INT_SUB INTB  */
#line 180 "src/ruleparse.y"
                  { *(yyvsp[0].big) = -*(yyvsp[0].big); (yyval.big) = (yyvsp[0].big); }
#line 1886 "src/ruleparse.cc"
    break;

  case 76: /* op_any: OP_BOOL_OR  */
#line 183 "src/ruleparse.y"
                               { (yyval.opcode) = CPUI_BOOL_OR; }
#line 1892 "src/ruleparse.cc"
    break;

  case 77: /* op_any: OP_BOOL_AND  */
#line 184 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_BOOL_AND; }
#line 1898 "src/ruleparse.cc"
    break;

  case 78: /* op_any: OP_BOOL_XOR  */
#line 185 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_BOOL_XOR; }
#line 1904 "src/ruleparse.cc"
    break;

  case 79: /* op_any: OP_BOOL_NEGATE  */
#line 186 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_BOOL_NEGATE; }
#line 1910 "src/ruleparse.cc"
    break;

  case 80: /* op_any: OP_INT_NEGATE  */
#line 187 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_INT_NEGATE; }
#line 1916 "src/ruleparse.cc"
    break;

  case 81: /* op_any: OP_INT_ADD  */
#line 188 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_INT_ADD; }
#line 1922 "src/ruleparse.cc"
    break;

  case 82: /* op_any: OP_INT_SUB  */
#line 189 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_INT_SUB; }
#line 1928 "src/ruleparse.cc"
    break;

  case 83: /* op_any: OP_INT_AND  */
#line 190 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_INT_AND; }
#line 1934 "src/ruleparse.cc"
    break;

  case 84: /* op_any: OP_INT_OR  */
#line 191 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_INT_OR; }
#line 1940 "src/ruleparse.cc"
    break;

  case 85: /* op_any: OP_INT_XOR  */
#line 192 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_INT_XOR; }
#line 1946 "src/ruleparse.cc"
    break;

  case 86: /* op_any: OP_INT_MULT  */
#line 193 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_INT_MULT; }
#line 1952 "src/ruleparse.cc"
    break;

  case 87: /* op_any: OP_INT_DIV  */
#line 194 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_INT_DIV; }
#line 1958 "src/ruleparse.cc"
    break;

  case 88: /* op_any: OP_INT_REM  */
#line 195 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_INT_REM; }
#line 1964 "src/ruleparse.cc"
    break;

  case 89: /* op_any: OP_INT_RIGHT  */
#line 196 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_INT_RIGHT; }
#line 1970 "src/ruleparse.cc"
    break;

  case 90: /* op_any: OP_INT_LEFT  */
#line 197 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_INT_LEFT; }
#line 1976 "src/ruleparse.cc"
    break;

  case 91: /* op_any: OP_INT_EQUAL  */
#line 198 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_INT_EQUAL; }
#line 1982 "src/ruleparse.cc"
    break;

  case 92: /* op_any: OP_INT_NOTEQUAL  */
#line 199 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_INT_NOTEQUAL; }
#line 1988 "src/ruleparse.cc"
    break;

  case 93: /* op_any: OP_INT_LESS  */
#line 200 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_INT_LESS; }
#line 1994 "src/ruleparse.cc"
    break;

  case 94: /* op_any: OP_INT_LESSEQUAL  */
#line 201 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_INT_LESSEQUAL; }
#line 2000 "src/ruleparse.cc"
    break;

  case 95: /* op_any: OP_INT_SDIV  */
#line 202 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_INT_SDIV; }
#line 2006 "src/ruleparse.cc"
    break;

  case 96: /* op_any: OP_INT_SREM  */
#line 203 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_INT_SREM; }
#line 2012 "src/ruleparse.cc"
    break;

  case 97: /* op_any: OP_INT_SRIGHT  */
#line 204 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_INT_SRIGHT; }
#line 2018 "src/ruleparse.cc"
    break;

  case 98: /* op_any: OP_INT_SLESS  */
#line 205 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_INT_SLESS; }
#line 2024 "src/ruleparse.cc"
    break;

  case 99: /* op_any: OP_INT_SLESSEQUAL  */
#line 206 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_INT_SLESSEQUAL; }
#line 2030 "src/ruleparse.cc"
    break;

  case 100: /* op_any: OP_INT_ZEXT  */
#line 207 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_INT_ZEXT; }
#line 2036 "src/ruleparse.cc"
    break;

  case 101: /* op_any: OP_INT_CARRY  */
#line 208 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_INT_CARRY; }
#line 2042 "src/ruleparse.cc"
    break;

  case 102: /* op_any: OP_INT_SEXT  */
#line 209 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_INT_SEXT; }
#line 2048 "src/ruleparse.cc"
    break;

  case 103: /* op_any: OP_INT_SCARRY  */
#line 210 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_INT_SCARRY; }
#line 2054 "src/ruleparse.cc"
    break;

  case 104: /* op_any: OP_INT_SBORROW  */
#line 211 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_INT_SBORROW; }
#line 2060 "src/ruleparse.cc"
    break;

  case 105: /* op_any: OP_FLOAT_ADD  */
#line 212 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_FLOAT_ADD; }
#line 2066 "src/ruleparse.cc"
    break;

  case 106: /* op_any: OP_FLOAT_SUB  */
#line 213 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_FLOAT_SUB; }
#line 2072 "src/ruleparse.cc"
    break;

  case 107: /* op_any: OP_FLOAT_MULT  */
#line 214 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_FLOAT_MULT; }
#line 2078 "src/ruleparse.cc"
    break;

  case 108: /* op_any: OP_FLOAT_DIV  */
#line 215 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_FLOAT_DIV; }
#line 2084 "src/ruleparse.cc"
    break;

  case 109: /* op_any: OP_FLOAT_EQUAL  */
#line 216 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_FLOAT_EQUAL; }
#line 2090 "src/ruleparse.cc"
    break;

  case 110: /* op_any: OP_FLOAT_NOTEQUAL  */
#line 217 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_FLOAT_NOTEQUAL; }
#line 2096 "src/ruleparse.cc"
    break;

  case 111: /* op_any: OP_FLOAT_LESS  */
#line 218 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_FLOAT_LESS; }
#line 2102 "src/ruleparse.cc"
    break;

  case 112: /* op_any: OP_FLOAT_LESSEQUAL  */
#line 219 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_FLOAT_LESSEQUAL; }
#line 2108 "src/ruleparse.cc"
    break;

  case 113: /* op_any: OP_FLOAT_NAN  */
#line 220 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_FLOAT_NAN; }
#line 2114 "src/ruleparse.cc"
    break;

  case 114: /* op_any: OP_FLOAT_ABS  */
#line 221 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_FLOAT_ABS; }
#line 2120 "src/ruleparse.cc"
    break;

  case 115: /* op_any: OP_FLOAT_SQRT  */
#line 222 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_FLOAT_SQRT; }
#line 2126 "src/ruleparse.cc"
    break;

  case 116: /* op_any: OP_FLOAT_CEIL  */
#line 223 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_FLOAT_CEIL; }
#line 2132 "src/ruleparse.cc"
    break;

  case 117: /* op_any: OP_FLOAT_FLOOR  */
#line 224 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_FLOAT_FLOOR; }
#line 2138 "src/ruleparse.cc"
    break;

  case 118: /* op_any: OP_FLOAT_ROUND  */
#line 225 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_FLOAT_ROUND; }
#line 2144 "src/ruleparse.cc"
    break;

  case 119: /* op_any: OP_FLOAT_INT2FLOAT  */
#line 226 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_FLOAT_INT2FLOAT; }
#line 2150 "src/ruleparse.cc"
    break;

  case 120: /* op_any: OP_FLOAT_FLOAT2FLOAT  */
#line 227 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_FLOAT_FLOAT2FLOAT; }
#line 2156 "src/ruleparse.cc"
    break;

  case 121: /* op_any: OP_FLOAT_TRUNC  */
#line 228 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_FLOAT_TRUNC; }
#line 2162 "src/ruleparse.cc"
    break;

  case 122: /* op_any: OP_BRANCH  */
#line 229 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_BRANCH; }
#line 2168 "src/ruleparse.cc"
    break;

  case 123: /* op_any: OP_BRANCHIND  */
#line 230 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_BRANCHIND; }
#line 2174 "src/ruleparse.cc"
    break;

  case 124: /* op_any: OP_CALL  */
#line 231 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_CALL; }
#line 2180 "src/ruleparse.cc"
    break;

  case 125: /* op_any: OP_CALLIND  */
#line 232 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_CALLIND; }
#line 2186 "src/ruleparse.cc"
    break;

  case 126: /* op_any: OP_RETURN  */
#line 233 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_RETURN; }
#line 2192 "src/ruleparse.cc"
    break;

  case 127: /* op_any: OP_CBRANCH  */
#line 234 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_CBRANCH; }
#line 2198 "src/ruleparse.cc"
    break;

  case 128: /* op_any: OP_CALLOTHER  */
#line 235 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_CALLOTHER; }
#line 2204 "src/ruleparse.cc"
    break;

  case 129: /* op_any: OP_LOAD  */
#line 236 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_LOAD; }
#line 2210 "src/ruleparse.cc"
    break;

  case 130: /* op_any: OP_STORE  */
#line 237 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_STORE; }
#line 2216 "src/ruleparse.cc"
    break;

  case 131: /* op_any: OP_PIECE  */
#line 238 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_PIECE; }
#line 2222 "src/ruleparse.cc"
    break;

  case 132: /* op_any: OP_SUBPIECE  */
#line 239 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_SUBPIECE; }
#line 2228 "src/ruleparse.cc"
    break;

  case 133: /* op_any: OP_COPY  */
#line 240 "src/ruleparse.y"
                           { (yyval.opcode) = CPUI_COPY; }
#line 2234 "src/ruleparse.cc"
    break;

  case 134: /* op_list: op_any  */
#line 243 "src/ruleparse.y"
                { (yyval.opcodelist) = new vector<OpCode>; (yyval.opcodelist)->push_back((yyvsp[0].opcode)); }
#line 2240 "src/ruleparse.cc"
    break;

  case 135: /* op_list: op_list op_any  */
#line 244 "src/ruleparse.y"
                 { (yyval.opcodelist) = (yyvsp[-1].opcodelist); (yyval.opcodelist)->push_back((yyvsp[0].opcode)); }
#line 2246 "src/ruleparse.cc"
    break;

  case 136: /* op_ident: OP_IDENTIFIER  */
#line 247 "src/ruleparse.y"
                        { (yyval.id) = rulecompile->findIdentifier((yyvsp[0].str)); }
#line 2252 "src/ruleparse.cc"
    break;

  case 137: /* var_ident: VAR_IDENTIFIER  */
#line 250 "src/ruleparse.y"
                          { (yyval.id) = rulecompile->findIdentifier((yyvsp[0].str)); }
#line 2258 "src/ruleparse.cc"
    break;

  case 138: /* const_ident: CONST_IDENTIFIER  */
#line 253 "src/ruleparse.y"
                              { (yyval.id) = rulecompile->findIdentifier((yyvsp[0].str)); }
#line 2264 "src/ruleparse.cc"
    break;

  case 139: /* op_new_ident: OP_NEW_IDENTIFIER  */
#line 256 "src/ruleparse.y"
                                { (yyval.id) = rulecompile->findIdentifier((yyvsp[0].str)); }
#line 2270 "src/ruleparse.cc"
    break;

  case 140: /* var_new_ident: VAR_NEW_IDENTIFIER  */
#line 259 "src/ruleparse.y"
                                  { (yyval.id) = rulecompile->findIdentifier((yyvsp[0].str)); }
#line 2276 "src/ruleparse.cc"
    break;


#line 2280 "src/ruleparse.cc"

      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT ("-> $$ =", YY_CAST (yysymbol_kind_t, yyr1[yyn]), &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;

  *++yyvsp = yyval;

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */
  {
    const int yylhs = yyr1[yyn] - YYNTOKENS;
    const int yyi = yypgoto[yylhs] + *yyssp;
    yystate = (0 <= yyi && yyi <= YYLAST && yycheck[yyi] == *yyssp
               ? yytable[yyi]
               : yydefgoto[yylhs]);
  }

  goto yynewstate;


/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYSYMBOL_YYEMPTY : YYTRANSLATE (yychar);
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
      yyerror (YY_("syntax error"));
    }

  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
         error, discard it.  */

      if (yychar <= YYEOF)
        {
          /* Return failure if at end of input.  */
          if (yychar == YYEOF)
            YYABORT;
        }
      else
        {
          yydestruct ("Error: discarding",
                      yytoken, &yylval);
          yychar = YYEMPTY;
        }
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:
  /* Pacify compilers when the user code never invokes YYERROR and the
     label yyerrorlab therefore never appears in user code.  */
  if (0)
    YYERROR;
  ++yynerrs;

  /* Do not reclaim the symbols of the rule whose action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;      /* Each real token shifted decrements this.  */

  /* Pop stack until we find a state that shifts the error token.  */
  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
        {
          yyn += YYSYMBOL_YYerror;
          if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYSYMBOL_YYerror)
            {
              yyn = yytable[yyn];
              if (0 < yyn)
                break;
            }
        }

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
        YYABORT;


      yydestruct ("Error: popping",
                  YY_ACCESSING_SYMBOL (yystate), yyvsp);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", YY_ACCESSING_SYMBOL (yyn), yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturnlab;


/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturnlab;


/*-----------------------------------------------------------.
| yyexhaustedlab -- YYNOMEM (memory exhaustion) comes here.  |
`-----------------------------------------------------------*/
yyexhaustedlab:
  yyerror (YY_("memory exhausted"));
  yyresult = 2;
  goto yyreturnlab;


/*----------------------------------------------------------.
| yyreturnlab -- parsing is finished, clean up and return.  |
`----------------------------------------------------------*/
yyreturnlab:
  if (yychar != YYEMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval);
    }
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
                  YY_ACCESSING_SYMBOL (+*yyssp), yyvsp);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif

  return yyresult;
}

#line 262 "src/ruleparse.y"


inline int ruleparselex(void)

{
  return rulecompile->nextToken();
}

int ruleparseerror(const char *s)

{
  rulecompile->ruleError(s);
  return 0;
}

#endif
