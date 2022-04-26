
import string, random

## Converts True or False string to Boolean type.
def str_to_bool(string):
  if string == 'true':
    return True
  elif string == 'false':
    return False
  else:
    print('Value was not True or False but {string}')
    raise ValueError

## Generates a random string of user defined length.
def generate_random_string(length):
    ## choose from all lowercase letter
    try:
        letters = string.ascii_lowercase
        result_str = ''.join(random.choice(letters) for i in range(length))
        return result_str
    except Exception as e:
        print(e)

if __name__ == '__main__':
  pass