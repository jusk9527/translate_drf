from Test_demo.django_autoreload import autoreload
from Test_demo.django_autoreload import test1_autoreload

def main():
    print("---------------------")
    print("test.main1")
    print("test.main2")
    print("test.main4")
    test1_autoreload.main()

if __name__ == '__main__':
    autoreload.run_with_reloader(main)
