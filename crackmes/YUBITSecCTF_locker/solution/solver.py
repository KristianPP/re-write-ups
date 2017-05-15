#!/usr/bin/env python

import angr


def main():
    p = angr.Project("./locker", load_options={'auto_load_libs': False})
    ex = p.surveyors.Explorer(find=(0x00400bd5,), avoid=(0x00400b7f, 0x00400beb))
    ex.run()

    return ex.found


if __name__ == '__main__':
    print main()
