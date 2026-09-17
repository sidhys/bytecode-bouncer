#include <cerrno>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include <unistd.h>

int main(int argc, char **argv) {
  std::vector<std::string> arguments{
      BOUNCER_DEMO_PYTHON, BOUNCER_DEMO_RUNNER,
      "--java", BOUNCER_DEMO_JAVA,
      "--agent", BOUNCER_DEMO_AGENT,
      "--classes", BOUNCER_DEMO_CLASSES,
      "--replacement", BOUNCER_DEMO_REPLACEMENT,
      "--java-agent", BOUNCER_DEMO_JAR,
      "--reports", BOUNCER_DEMO_REPORTS};
  for (int i = 1; i < argc; ++i) {
    arguments.emplace_back(argv[i]);
  }
  std::vector<char *> command;
  for (auto &argument : arguments) {
    command.push_back(argument.data());
  }
  command.push_back(nullptr);
  execv(command.front(), command.data());
  std::cerr << "unable to start JVM demo runner: " << std::strerror(errno) << '\n';
  return 1;
}
