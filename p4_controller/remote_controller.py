from json import load
from argparse import ArgumentParser
from p4runtime_lib.simple_controller_remote import P4RuntimeController


class ControllerRunner:

    def __init__(self, topo_file, logs, quiet):
        self.topo_file = topo_file
        self.logs_dir = logs
        self.quiet = quiet

        hosts, switches, links = self.parse_topology()
        self.controller = P4RuntimeController(switches, hosts, links, self.quiet, self.logs_dir)

    def parse_topology(self):
        print(f'Reading topology file: {self.topo_file}')
        with open(self.topo_file, 'r') as f:
            topo = load(f)
        return topo['hosts'], topo['switches'], topo['links']

    def start_tasks(self):
        self.controller.program_switches()
        self.controller.start_packet_in_manager()

    def command_line(self):
        while True:
            cmd = input("lkn-p4-controller> ")
            cmd_components = cmd.split(' ')
            if 'topology' in cmd and len(cmd_components) == 1:
                self.controller.print_topology()
            elif 'quit' in cmd:
                print("Leaving.")
                break
            else:
                print("Unknown command.\nAvailable commands topology or quit.")


def get_args():
    parser = ArgumentParser()
    parser.add_argument('-t', '--topo', help='Path to topology json', type=str, required=False, default='./topology.json')
    parser.add_argument('-l', '--log', help='Path to logs dir', type=str, required=False, default='./logs')
    parser.add_argument('-q', '--quiet', help='Suppress log messages.', action='store_true', required=False, default=False)
    return parser.parse_args()


if __name__ == '__main__':
    args = get_args()
    controller = ControllerRunner(args.topo, args.log, args.quiet)
    controller.start_tasks()
    controller.command_line()
