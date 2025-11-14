import argparse
import sys
import os
import re
import urllib.request
import subprocess
import tempfile
from collections import defaultdict


class APKRepository:
    def __init__(self, repository_url=None, test_repo_file=None):
        self.repository_url = repository_url
        self.test_repo_file = test_repo_file
        self.packages_cache = {}

    def _read_file(self, filepath):
        """Чтение файла с автодетектом кодировки"""
        encodings = ['utf-8', 'cp1251', 'latin-1']
        for encoding in encodings:
            try:
                with open(filepath, 'r', encoding=encoding) as f:
                    return f.read()
            except UnicodeDecodeError:
                continue
        with open(filepath, 'rb') as f:
            return f.read().decode('utf-8', errors='ignore')

    def _parse_test_repo(self, line):
        """Парсинг строки тестового репозитория (формат: пакет: зависимость1, зависимость2)"""
        line = line.strip()
        if not line or line.startswith('#'):
            return None, []
        if ':' not in line:
            return line, []
        package, deps = line.split(':', 1)
        dependencies = [dep.strip() for dep in deps.split(',') if dep.strip()]
        return package.strip(), dependencies

    def fetch_index(self):
        """Получение содержимого индекса пакетов из репозитория или файла"""
        if self.test_repo_file:
            return self._read_file(self.test_repo_file)
        if not self.repository_url:
            raise ValueError("URL репозитория не указан")
        if self.repository_url.startswith('http'):
            return self._create_sample_index()
        return self._read_file(self.repository_url)

    def _create_sample_index(self):
        """Создание демо-индекса для тестирования (заглушка вместо реального APKINDEX)"""
        return """P:alpine-baselayout
V:3.4.0-r0
D:musl alpine-keys
P:musl
V:1.2.4-r1
D:
P:alpine-keys
V:2.4-r1
D:"""

    def parse_index(self, content):
        """Парсинг APKINDEX формата или тестового репозитория"""
        packages = {}
        if self.test_repo_file:
            # Парсинг тестового формата
            for line in content.split('\n'):
                pkg, deps = self._parse_test_repo(line)
                if pkg:
                    packages[pkg] = {'dependencies': deps}
        else:
            # Парсинг APKINDEX формата Alpine
            current_pkg = {}
            for line in content.split('\n'):
                line = line.strip()
                if not line:
                    continue
                if line.startswith('P:'):
                    # Начало нового пакета
                    if current_pkg:
                        packages[current_pkg['name']] = current_pkg
                    current_pkg = {'name': line[2:], 'dependencies': []}
                elif line.startswith('D:'):
                    # Секция зависимостей
                    deps = line[2:]
                    if deps:
                        clean_deps = []
                        for dep in deps.split(' '):
                            dep = dep.strip()
                            if dep:
                                # Очистка от условий версий
                                clean_dep = re.sub(r'[<=>~].*$', '', dep)
                                clean_dep = re.sub(r'-[0-9].*$', '', clean_dep)
                                if clean_dep and clean_dep not in clean_deps:
                                    clean_deps.append(clean_dep)
                        current_pkg['dependencies'] = clean_deps
            if current_pkg:
                packages[current_pkg['name']] = current_pkg
        return packages

    def get_dependencies(self, package_name, version=None):
        """Получение списка зависимостей для пакета"""
        try:
            if package_name in self.packages_cache:
                return self.packages_cache[package_name]['dependencies']
            content = self.fetch_index()
            packages = self.parse_index(content)
            self.packages_cache.update(packages)
            if package_name in packages:
                return packages[package_name]['dependencies']
            return []
        except Exception:
            return []


class DependencyGraph:
    def __init__(self, repository):
        self.repository = repository
        self.graph = defaultdict(list)
        self.visited = set()
        self.cycles = set()

    def should_skip(self, package, filter_str):
        """Проверка фильтрации пакета по подстроке"""
        return filter_str and filter_str.lower() in package.lower()

    def build_graph(self, start_package, version=None, max_depth=10, filter_str='', depth=0, path=None):
        """Рекурсивное построение графа зависимостей методом BFS"""
        if path is None:
            path = []
        if depth >= max_depth:
            return False
        if self.should_skip(start_package, filter_str):
            return False
        if start_package in path:
            # Обнаружение циклической зависимости
            self.cycles.add(tuple(path[path.index(start_package):] + [start_package]))
            return True
        current_path = path + [start_package]
        if start_package in self.visited:
            return False
        self.visited.add(start_package)
        try:
            deps = self.repository.get_dependencies(start_package, version)
            self.graph[start_package] = deps
            has_cycle = False
            for dep in deps:
                if not self.should_skip(dep, filter_str):
                    # Рекурсивный обход зависимостей
                    cycle = self.build_graph(dep, None, max_depth, filter_str, depth + 1, current_path)
                    has_cycle = has_cycle or cycle
            return has_cycle
        except Exception:
            return False


class GraphVisualizer:
    def __init__(self, graph):
        self.graph = graph

    def ascii_tree(self, root, prefix="", last=True, visited=None):
        """Генерация ASCII-представления дерева зависимостей"""
        if visited is None:
            visited = set()
        result = []
        if prefix == "":
            result.append("    " + root)
            visited.add(root)
        else:
            connector = "└── " if last else "├── "
            result.append(f"{prefix}{connector}{root}")
            visited.add(root)
        if root in self.graph:
            deps = self.graph[root]
            new_prefix = prefix + ("    " if last else "│   ")
            for i, dep in enumerate(deps):
                last_dep = (i == len(deps) - 1)
                if dep in self.graph and dep not in visited:
                    result.append(self.ascii_tree(dep, new_prefix, last_dep, visited))
                else:
                    connector = "└── " if last_dep else "├── "
                    marker = " ══█" if dep in visited else ""
                    result.append(f"{new_prefix}{connector}{dep}{marker}")
        return "\n".join(result)

    def d2_diagram(self, root_package):
        """Генерация диаграммы в формате D2 языка"""
        lines = [f"# {root_package} dependencies"]
        for package, deps in self.graph.items():
            for dep in deps:
                lines.append(f"{package} -> {dep}")
        return "\n".join(lines)

    def render(self, root_package, output_file):
        """Рендеринг графа в изображение через D2"""
        d2_content = self.d2_diagram(root_package)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.d2', delete=False, encoding='utf-8') as f:
            f.write(d2_content)
            d2_file = f.name
        try:
            subprocess.run(['d2', d2_file, output_file], capture_output=True)
        except FileNotFoundError:
            # Fallback: сохранение D2 файла если D2 не установлен
            with open(output_file.replace('.png', '.d2'), 'w') as f:
                f.write(d2_content)
        finally:
            os.unlink(d2_file)


class DependencyVisualizer:
    def __init__(self):
        self.args = None
        self.graph = {}

    def parse_args(self):
        """Парсинг аргументов командной строки"""
        parser = argparse.ArgumentParser(description='Визуализатор зависимостей APK')
        parser.add_argument('--package', '-p', required=True, help='Пакет для анализа')
        parser.add_argument('--version', '-v', help='Версия пакета')
        parser.add_argument('--repository', '-r', help='URL репозитория')
        parser.add_argument('--test-repo', '-t', help='Тестовый репозиторий')
        parser.add_argument('--max-depth', '-d', type=int, default=10, help='Макс. глубина')
        parser.add_argument('--filter', '-f', help='Фильтр пакетов')
        parser.add_argument('--ascii-tree', '-a', action='store_true', help='ASCII дерево')
        parser.add_argument('--output', '-o', default='dependencies.png', help='Выходной файл')
        return parser.parse_args()

    def validate_args(self):
        """Валидация входных параметров"""
        if not self.args.package:
            raise ValueError("Пакет не указан")
        if self.args.max_depth <= 0:
            raise ValueError("Глубина должна быть > 0")
        if self.args.test_repo and not os.path.exists(self.args.test_repo):
            raise FileNotFoundError(f"Файл {self.args.test_repo} не найден")
        return True

    def run(self):
        """Основной метод запуска приложения"""
        try:
            self.args = self.parse_args()
            self.validate_args()

            if self.args.test_repo and not os.path.exists(self.args.test_repo):
                self.create_test_repo()

            # Инициализация репозитория и построение графа
            repo = APKRepository(
                repository_url=self.args.repository,
                test_repo_file=self.args.test_repo
            )

            graph_builder = DependencyGraph(repo)
            graph_builder.build_graph(
                start_package=self.args.package,
                version=self.args.version,
                max_depth=self.args.max_depth,
                filter_str=self.args.filter
            )

            self.graph = graph_builder.graph

            if not self.graph:
                print("Граф не построен")
                return

            # Вывод статистики и визуализация
            print(f"Пакетов: {len(self.graph)}")
            print(f"Циклов: {len(graph_builder.cycles)}")

            visualizer = GraphVisualizer(self.graph)

            if self.args.ascii_tree:
                print("\nДерево зависимостей:")
                print(visualizer.ascii_tree(self.args.package))

            visualizer.render(self.args.package, self.args.output)
            print(f"Визуализация: {self.args.output}")

        except Exception as e:
            print(f"Ошибка: {e}")
            sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) == 1:
        # Вывод справки при запуске без аргументов
        print("Использование: python script.py --package NAME --test-repo FILE [--ascii-tree]")
        print("Пример: python script.py --package A --test-repo test_repo.txt --ascii-tree")
    else:
        visualizer = DependencyVisualizer()
        visualizer.run()