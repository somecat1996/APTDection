# Dataset Interface

 > __NB__: currently, only make dataset of `Background_PC` group

### Multiprocessing Interface

```python
dataset.dataset(*args, mode)
```

##### Cook dataset for CNN.

 - Positional arguments:
    * `path` -- `str`, **absolute** source path

 - Keyword arguments:
    * `mode` -- `int`, preparation mode
    
        | MODE | DESCRIPTION | LABELING | FINGERPRINTS |
        | :--: | :---------: | :------: | :----------: |
        | `0`  |   stage 0   |   True   |    False     |
        | `1`  |   stage 1   |   True   |     True     |
        | `2`  |   stage 2   |  False   |     True     |

 - Returns:
    * `dict` -- dataset index

 - Note:
 	* flowed PCAP files stored in `./stream/*/tmp`
 	* index of flowed PCAP files stored in `./stream/*/stream.json`
 	* dataset files stored in `./dataset` according to its kinds and labels
 	* index of dataset stored in `./dataset/index.json`

### JSON Interface

```python
dataset.make_dataset(name, *, labels=None)
```

##### Make dataset.

 - Positional arguments:
    * `name` -- `str`, dataset source name

 - Keyword arguments:
    * `labels` -- `dict`, dataset labels

 - Returns:
    * `dict` -- dataset index

 - Note:
 	* `name` must be **file-name-only**, without root directory nor file extension
 	* if `labels` set to `None`, then read stream index from corresponding `stream.json`
