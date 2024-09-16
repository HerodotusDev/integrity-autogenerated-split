from starkware.cairo.lang.compiler.parser import parse_file
from starkware.cairo.lang.compiler.ast.code_elements import *
from starkware.cairo.lang.compiler.ast.expr import *
from starkware.cairo.lang.compiler.ast.expr_func_call import *
import requests

global array_read_offset
global constants

functions = {
    'eval_composition_polynomial': """\
fn eval_composition_polynomial_inner(
    mut mask_values: Span<felt252>,
    mut constraint_coefficients: Span<felt252>,
    point: felt252,
    trace_generator: felt252,
    global_values: GlobalValues,
) -> felt252""",
    'eval_oods_polynomial': """\
fn eval_oods_polynomial_inner(
    mut column_values: Span<felt252>,
    mut oods_values: Span<felt252>,
    mut constraint_coefficients: Span<felt252>,
    point: felt252,
    oods_point: felt252,
    trace_generator: felt252,
) -> felt252""",
}


def eval(node: AstNode) -> int:
    match node:
        case ExprOperator(a=a, b=b, op='+'):
            return eval(a) + eval(b)
        
        case ExprIdentifier(name=name) if name in constants:
            return constants[name]

        case ExprConst(val=val):
            return val

    print(node.__class__.__name__, 'not implemented in eval')
    print(node, "\n")
    return 0


def rename_var(name: str) -> str:
    return name.replace("__", "_")


def parse(node: AstNode, comment: str = '') -> str:
    global array_read_offset
    match node:
        case CodeBlock(code_elements=code_elements):
            acc = ''
            for ce in code_elements:
                acc += parse(ce)
            return acc

        case CodeElementAllocLocals(): # alloc_locals
            return ''
        
        case CodeElementLocalVariable( # local x
            typed_identifier=TypedIdentifier(
                identifier=ExprIdentifier(name=name)
            ),
            expr=expr
        ) | CodeElementUnpackBinding( # let (local x)
            unpacking_list=IdentifierList(
                identifiers=[
                    TypedIdentifier(identifier=ExprIdentifier(name=name))
                ]
            ),
            rvalue=expr
        ) | CodeElementTemporaryVariable( # tempvar x
            typed_identifier=TypedIdentifier(
                identifier=ExprIdentifier(name=name)
            ),
            expr=expr
        ):
            com = '' if comment is None else (' //' + comment)
            return f"let {name} = {parse(expr)};{com}\n\t"
    
        case RvalueFuncCall( # safe_div(x, y)
            func_ident=ExprIdentifier(name='safe_div'),
            arguments=ArgList(args=[
                lv,
                rv
            ])
        ):
            # TODO: should this be safe_div?
            return f"{parse(lv)} / {parse(rv)}"

        case RvalueFuncCall( # safe_mult(x,y)
            func_ident=ExprIdentifier(name='safe_mult'),
            arguments=ArgList(args=[
                lv,
                rv
            ])
        ):
            # TODO: should this be safe_mult?
            return f"{parse(lv)} * {parse(rv)}"

        case RvalueFuncCall( # f(x, y, ...)
            func_ident=ExprIdentifier(name=name),
            arguments=ArgList(args=args),
        ):
            def remove_parenthesis(arg):
                match arg:
                    case ExprAssignment(expr=ExprParentheses(val=val)):
                        return val
                return arg
            return f"{name}({', '.join([parse(remove_parenthesis(arg)) for arg in args])})"
        
        case ExprOperator(a=a, b=b, op=op):
            return f"{parse(a)} {op} {parse(b)}"

        case ExprSubscript( # x[0]
            expr=ExprIdentifier(name=name),
            offset=ExprConst(val=val)
        ) if val == array_read_offset.get(name, 0):
            array_read_offset[name] = array_read_offset.get(name, 0) + 1
            return f"*{name}.pop_front().unwrap()"

        case ExprSubscript( # x[CONST_VAR]
            expr=ExprIdentifier(name=name),
            offset=offset
        ):
            evaluated_offset = eval(offset)
            curr = array_read_offset.get(name, 0)
            if curr != evaluated_offset:
                print(f"Array read not subsequent. Expected {curr}, actual {evaluated_offset}")
            else:
                array_read_offset[name] = curr + 1
                return f"*{name}.pop_front().unwrap()"
        
        case CodeElementStaticAssert(a=a, b=b): # static assert x == y
            return f"assert({parse(a)} == {parse(b)}, 'Assert failed');\n\t"

        case CodeElementReturn( # return (res=x)
            expr=ExprTuple(
                members=ArgList(
                    args=[
                        ExprAssignment(
                            identifier=ExprIdentifier(name='res'),
                            expr=ExprIdentifier(name=var),
                        )
                    ]
                )
            )
        ):
            return f"return {var};\n"
        
        case ExprParentheses(val=val): # (x)
            return f"({parse(val)})"

        case ExprIdentifier(name=name): # x
            return rename_var(name)
        
        case ExprConst(format_str=format_str):
            return format_str
        
        case ExprAssignment(expr=expr):
            return parse(expr)
        
        case ExprFuncCall(rvalue=rvalue):
            return parse(rvalue)

        case CommentedCodeElement(code_elm=code_elm, comment=comment):
            return parse(code_elm, comment)

        case CodeElementEmptyLine():
            if comment is None:
                return '\n\t'
            return '//' + comment + '\n\t'

    print(node.__class__.__name__, 'not implemented')
    print(node, "\n")
    return ''


def handle_github_file(url, output_file):
    global array_read_offset
    response = requests.get(url)
    if response.status_code != 200:
        raise Exception(f"Failed to fetch {url}")

    ast = parse_file(response.text, filename='autogenerated.cairo')

    global constants
    constants = {}

    functions_result = {}
    for commented_code_element in ast.code_block.code_elements:
        match commented_code_element.code_elm:
            case CodeElementFunction(
                element_type='func',
                identifier=ExprIdentifier(name=name),
                code_block=code_block
            ) if name in functions:
                array_read_offset = {}
                parsed = parse(code_block)
                if name in functions_result:
                    raise Exception(name + ' defined multiple times')
                functions_result[name] = functions[name] + ' {' + parsed + "}\n"
            case CodeElementConst(identifier=ExprIdentifier(name=name), expr=expr):
                constants[name] = eval(expr)

    with open(output_file, 'w') as f:
        f.write('\n'.join(functions_result.values()))


def main():
    layouts = ('recursive', 'recursive_with_poseidon', 'small', 'dex', 'starknet', 'starknet_with_keccak')

    for layout in layouts:
        handle_github_file(
            f"https://raw.githubusercontent.com/starkware-libs/cairo-lang/master/src/starkware/cairo/stark_verifier/air/layouts/{layout}/autogenerated.cairo",
            f"output/{layout}.cairo"
        )


if __name__ == '__main__':
    main()
